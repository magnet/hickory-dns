// Measures the longest single poll of the tasks that receive a DNS response over TCP.
//
// Run with:
//
//   cargo bench -p hickory-net --bench response_poll [-- RECORDS...]
//
// A blocking server on its own thread answers every query with the same SRV response. The client
// runs on a single-threaded Tokio runtime, and times every poll of the exchange's background task
// and of the request future. For each lookup it keeps the longest poll of each, then reports the
// distribution over all lookups. A long poll holds the executor thread, so other tasks on it
// wait for at least that long.

use std::{
    env,
    future::Future,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

use hickory_net::{
    DnsHandle, DnsMultiplexer,
    proto::{
        op::{DnsRequest, DnsRequestOptions, Message, Query},
        rr::{Name, RData, Record, RecordType, rdata::SRV},
    },
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
    xfer::DnsExchange,
};

const WARMUP: usize = 200;
const LOOKUPS: usize = 2_000;

fn main() {
    let records = env::args()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect::<Vec<usize>>();
    let records = match records.is_empty() {
        true => vec![16, 256],
        false => records,
    };

    println!("{LOOKUPS} lookups over TCP, longest poll per lookup:");
    for count in records {
        measure(count);
    }
}

fn measure(records: usize) {
    let addr = serve(records);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (background, request) = runtime.block_on(async move {
        let (connect, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
        let multiplexer = DnsMultiplexer::new(connect.await.unwrap(), sender);
        let (exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(multiplexer);

        let background_max = Arc::new(AtomicU64::new(0));
        tokio::spawn(Timed::new(background, background_max.clone()));

        let name = Name::from_ascii("_service._tcp.example.com.").unwrap();
        let mut background_polls = Vec::with_capacity(LOOKUPS);
        let mut request_polls = Vec::with_capacity(LOOKUPS);
        for i in 0..WARMUP + LOOKUPS {
            background_max.store(0, Ordering::Relaxed);
            let request_max = Arc::new(AtomicU64::new(0));
            let request = DnsRequest::from_query(
                Query::new(name.clone(), RecordType::SRV),
                DnsRequestOptions::default(),
            );
            let response = Timed::new(exchange.send(request), request_max.clone())
                .await
                .unwrap();
            assert_eq!(response.answers.len(), records);

            if i >= WARMUP {
                background_polls.push(background_max.load(Ordering::Relaxed));
                request_polls.push(request_max.load(Ordering::Relaxed));
            }
        }

        (background_polls, request_polls)
    });

    println!("  {records} records:");
    report("background task", background);
    report("request future", request);
}

fn report(task: &str, mut nanos: Vec<u64>) {
    nanos.sort_unstable();
    let at = |quantile: f64| {
        let index = ((nanos.len() - 1) as f64 * quantile) as usize;
        Duration::from_nanos(nanos[index])
    };
    println!(
        "    {task:<16} p50 {:>10.1?}  p90 {:>10.1?}  p99 {:>10.1?}",
        at(0.5),
        at(0.9),
        at(0.99),
    );
}

/// Starts a server that answers every query on one connection with `records` SRV records.
fn serve(records: usize) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();

    let name = Name::from_ascii("_service._tcp.example.com.").unwrap();
    let mut response = Message::query();
    response.add_query(Query::new(name.clone(), RecordType::SRV));
    for i in 0..records {
        let target = Name::from_ascii(format!("host-{i}.example.com.")).unwrap();
        response.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::SRV(SRV::new(10, 10, 8080, target)),
        ));
    }
    let response = response.into_response().to_vec().unwrap();
    let mut framed = u16::try_from(response.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(&response);

    thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_nodelay(true).unwrap();
        let mut query = Vec::new();
        loop {
            let mut length = [0; 2];
            if socket.read_exact(&mut length).is_err() {
                return;
            }
            query.resize(usize::from(u16::from_be_bytes(length)), 0);
            socket.read_exact(&mut query).unwrap();

            // The response carries the ID of the query it answers.
            framed[2..4].copy_from_slice(&query[..2]);
            socket.write_all(&framed).unwrap();
        }
    });

    addr
}

/// Records the longest single poll of the wrapped future.
struct Timed<F> {
    future: Pin<Box<F>>,
    longest: Arc<AtomicU64>,
}

impl<F> Timed<F> {
    fn new(future: F, longest: Arc<AtomicU64>) -> Self {
        Self {
            future: Box::pin(future),
            longest,
        }
    }
}

impl<F: Future> Future for Timed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let start = Instant::now();
        let poll = self.future.as_mut().poll(cx);
        let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.longest.fetch_max(elapsed, Ordering::Relaxed);
        poll
    }
}

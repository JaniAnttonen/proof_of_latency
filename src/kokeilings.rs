use std::thread;
use futures::sync::oneshot;
use futures::*;

let (p, c) = oneshot::channel::<i32>();

thread::spawn(|| {
    c.map(|i| {
        println!("got: {}", i);
    }).wait();
});

p.send(3).unwrap();

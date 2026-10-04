use potlatch::{Book, Identity};

fn main() {
    let gpu_org = Identity::generate(); // owns the big hardware
    let small_org = Identity::generate(); // wants inference done
    let mut book = Book::new();

    // Under treaty t-7, small_org owes gpu_org 1200 compute-seconds.
    let iou = book.issue(
        &gpu_org,
        &small_org.public_key(),
        "t-7",
        "compute-seconds",
        1200,
        None,
    );
    let iou = book.accept(iou, &small_org).unwrap();
    println!(
        "iou issued: {}… — 1200 compute-seconds under t-7",
        &iou.id[..16]
    );

    // Work performed in three bursts; creditor settles as invoices land.
    let inv1 = book.invoke(&small_org, &iou.id, 400);
    book.settle(&gpu_org, &iou.id, &[&inv1.id]).unwrap();
    println!(
        "after first settlement: {} remaining",
        book.balance(&iou.id).unwrap()
    );

    let inv2 = book.invoke(&small_org, &iou.id, 400);
    book.settle(&gpu_org, &iou.id, &[&inv2.id]).unwrap();
    println!("after second: {} remaining", book.balance(&iou.id).unwrap());

    // small_org stalls — creditor puts the default on the permanent record.
    book.declare_default(&gpu_org, &iou.id, "90 days past due")
        .unwrap();
    println!(
        "credit report: {} default(s) on record",
        book.defaults(&small_org.public_key()).len()
    );
    println!(
        "outstanding obligations: {:?}",
        book.obligations(&small_org.public_key())
    );

    book.verify().unwrap();
    println!(
        "book: {} events, all signatures verified",
        book.events.len()
    );
}

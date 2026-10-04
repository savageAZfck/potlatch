use potlatch::{Book, Error, Identity};

fn setup() -> (Identity, Identity, Book) {
    let creditor = Identity::generate();
    let debtor = Identity::generate();
    let book = Book::new();
    (creditor, debtor, book)
}

#[test]
fn full_cycle_issue_accept_invoke_settle() {
    let (creditor, debtor, mut book) = setup();
    let iou = book.issue(
        &creditor,
        &debtor.public_key(),
        "t-1",
        "compute-seconds",
        600,
        None,
    );
    assert!(!iou.accepted());
    let iou = book.accept(iou, &debtor).unwrap();
    assert!(iou.accepted());

    let inv1 = book.invoke(&debtor, &iou.id, 200);
    let inv2 = book.invoke(&debtor, &iou.id, 150);
    book.settle(&creditor, &iou.id, &[&inv1.id, &inv2.id])
        .unwrap();

    assert_eq!(book.balance(&iou.id).unwrap(), 250);
    book.verify().unwrap();
}

#[test]
fn debtor_must_accept_for_real_debt() {
    let (creditor, debtor, mut book) = setup();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    iou.verify().unwrap(); // creditor half valid even pending
    assert!(!iou.accepted());
}

#[test]
fn wrong_party_cannot_accept() {
    let (creditor, debtor, mut book) = setup();
    let ringer = Identity::generate();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    assert!(matches!(
        book.accept(iou, &ringer),
        Err(Error::WrongParty(_))
    ));
}

#[test]
fn oversettlement_refused() {
    let (creditor, debtor, mut book) = setup();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let iou = book.accept(iou, &debtor).unwrap();
    let inv = book.invoke(&debtor, &iou.id, 250); // claim more than owed
    match book.settle(&creditor, &iou.id, &[&inv.id]) {
        Err(Error::OverSettled {
            attempted,
            remaining,
        }) => {
            assert_eq!(attempted, 250);
            assert_eq!(remaining, 100);
        }
        _ => panic!("should refuse oversettlement"),
    }
}

#[test]
fn invocation_for_wrong_iou_refused() {
    let (creditor, debtor, mut book) = setup();
    let a = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let b = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let a = book.accept(a, &debtor).unwrap();
    let b = book.accept(b, &debtor).unwrap();
    let inv_for_b = book.invoke(&debtor, &b.id, 50);
    assert!(book.settle(&creditor, &a.id, &[&inv_for_b.id]).is_err());
}

#[test]
fn non_creditor_cannot_settle_or_default() {
    let (creditor, debtor, mut book) = setup();
    let stranger = Identity::generate();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let iou = book.accept(iou, &debtor).unwrap();
    let inv = book.invoke(&debtor, &iou.id, 10);
    assert!(book.settle(&stranger, &iou.id, &[&inv.id]).is_err());
    assert!(book.declare_default(&stranger, &iou.id, "nope").is_err());
}

#[test]
fn defaults_are_part_of_credit_history() {
    let (creditor, debtor, mut book) = setup();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let iou = book.accept(iou, &debtor).unwrap();
    book.declare_default(&creditor, &iou.id, "past due, unsettled")
        .unwrap();
    assert_eq!(book.defaults(&debtor.public_key()), vec![iou.id.clone()]);
    assert_eq!(book.defaults(&creditor.public_key()).len(), 0);
}

#[test]
fn obligations_track_outstanding() {
    let (creditor, debtor, mut book) = setup();
    let a = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let b = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 40, None);
    let a = book.accept(a, &debtor).unwrap();
    let b = book.accept(b, &debtor).unwrap();
    let inv = book.invoke(&debtor, &a.id, 100); // fully pays a
    book.settle(&creditor, &a.id, &[&inv.id]).unwrap();
    let obs = book.obligations(&debtor.public_key());
    assert_eq!(obs.len(), 1);
    assert_eq!(obs[&b.id], 40);
}

#[test]
fn tampered_book_fails_verify() {
    let (creditor, debtor, mut book) = setup();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    book.accept(iou, &debtor).unwrap();
    let mut forged = book.clone();
    // Debtor tries to shrink the recorded debt.
    if let potlatch::EventKind::Accept { iou } = &mut forged.events[1].kind {
        iou.amount = 5;
    }
    assert!(forged.verify().is_err());
}

#[test]
fn double_accept_refused() {
    let (creditor, debtor, mut book) = setup();
    let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "tokens", 100, None);
    let iou = book.accept(iou.clone(), &debtor).unwrap();
    assert!(book.accept(iou, &debtor).is_err());
}

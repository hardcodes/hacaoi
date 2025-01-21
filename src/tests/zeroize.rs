use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq)]
struct DropOnZeroizeImplemented(u64);

impl Drop for DropOnZeroizeImplemented {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[test]
fn drop_on_zeroize_implemented() {
    let mut arr = [DropOnZeroizeImplemented(42); 1];
    unsafe { core::ptr::drop_in_place(&mut arr) };
    assert_eq!(arr.as_ref(), [DropOnZeroizeImplemented(0); 1].as_ref());
}

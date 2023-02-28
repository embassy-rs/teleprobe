use std::mem::MaybeUninit;

pub struct OnDrop<F: FnOnce()> {
    f: MaybeUninit<F>,
}

#[allow(unused)]
impl<F: FnOnce()> OnDrop<F> {
    pub fn new(f: F) -> Self {
        Self { f: MaybeUninit::new(f) }
    }

    #[allow(unused)]
    pub fn defuse(self) {
        std::mem::forget(self)
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}

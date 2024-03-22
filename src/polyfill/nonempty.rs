use core::num::NonZeroUsize;

#[derive(Clone, Copy)]
pub struct Slice<'a, T>(&'a [T]);

impl<'a, T> Slice<'a, T> {
    #[inline(always)]
    pub fn new(slice: &'a [T]) -> Option<Self> {
        NonZeroUsize::new(slice.len()).map(|_len| Self(slice))
    }
}

impl<T> Slice<'_, T> {
    #[inline(always)]
    pub fn len(&self) -> NonZeroUsize {
        let len = self.0.len();
        debug_assert_ne!(len, 0);
        // SAFETY: All constructors check that the inner slice is non-empty.
        unsafe { NonZeroUsize::new_unchecked(len) }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const T {
        self.0.as_ptr()
    }
}

impl<'a, T> From<Slice<'a, T>> for &'a [T] {
    #[inline(always)]
    fn from(Slice(slice): Slice<'a, T>) -> Self {
        slice
    }
}

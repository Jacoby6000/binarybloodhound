use patternsleuth::resolvers::{ResolveError, Result};

mod sealed {
    pub trait Sealed {}
}

/// Resolution shape. Execution stores candidates internally as a vector.
pub trait Cardinality: sealed::Sealed + Send + Sync + 'static {
    type Output<T: Send>: Send;

    #[doc(hidden)]
    fn finish<T: Send>(items: Vec<T>) -> Result<Self::Output<T>>;

    #[doc(hidden)]
    fn into_items<T: Send>(output: Self::Output<T>) -> Vec<T>;
}

/// Zero, one, or more candidates; resolves to `Vec<T>`.
#[derive(Debug, Clone, Copy)]
pub struct Variable;

/// Exactly one candidate; resolves to T.
#[derive(Debug, Clone, Copy)]
pub struct ExactlyOne;

impl sealed::Sealed for Variable {}
impl sealed::Sealed for ExactlyOne {}

impl Cardinality for Variable {
    type Output<T: Send> = Vec<T>;

    fn finish<T: Send>(items: Vec<T>) -> Result<Vec<T>> {
        Ok(items)
    }

    fn into_items<T: Send>(output: Vec<T>) -> Vec<T> {
        output
    }
}

impl Cardinality for ExactlyOne {
    type Output<T: Send> = T;

    fn finish<T: Send>(mut items: Vec<T>) -> Result<T> {
        if items.len() != 1 {
            return Err(ResolveError::new_msg(format!(
                "expected exactly one candidate, found {}",
                items.len()
            )));
        }
        Ok(items.pop().unwrap())
    }

    fn into_items<T: Send>(output: T) -> Vec<T> {
        vec![output]
    }
}

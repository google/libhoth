// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::future::Future;

thread_local! {
    static LOCAL_TOKIO: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
}

/// Runs a future to completion on the current thread.
///
/// This uses a thread-local tokio runtime.
///
/// # Panics
///
/// This function panics if called from an async execution context.
pub fn block_on<F: Future>(f: F) -> F::Output {
    LOCAL_TOKIO.with(|rt| rt.block_on(f))
}

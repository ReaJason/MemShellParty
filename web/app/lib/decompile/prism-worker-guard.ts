/**
 * prismjs auto-registers a `message` listener when loaded inside a Web Worker
 * (it expects JSON strings and calls JSON.parse on evt.data). Our worker
 * exchanges structured-clone objects, which crashes that handler with an
 * uncaught SyntaxError. Setting `self.Prism.disableWorkerMessageHandler`
 * before prism-core evaluates suppresses the registration.
 *
 * Imported for side effects before any prismjs import — ES module evaluation
 * order guarantees this runs first.
 */
(globalThis as unknown as { Prism: { disableWorkerMessageHandler: boolean } }).Prism = {
  disableWorkerMessageHandler: true,
};

export {};

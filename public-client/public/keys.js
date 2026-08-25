// The storage keys and channel/window names app.js and callback.js both use
// to hand a result across the popup boundary — one module so a change to
// one file can't silently stop the other from listening.
export const STASH_KEY = 'login-with-rezen:flow';
export const SESSION_KEY = 'login-with-rezen:session';
export const CHANNEL_NAME = 'login-with-rezen';
export const POPUP_NAME = 'login-with-rezen';

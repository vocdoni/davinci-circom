import { Buffer } from 'buffer';
import process from 'process';

if (typeof window !== 'undefined') {
    window.Buffer = Buffer;
    window.process = process;
    window.global = window;
} else if (typeof self !== 'undefined') {
    self.Buffer = Buffer;
    self.process = process;
    self.global = self;
}

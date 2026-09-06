#!/usr/bin/env node
import { main } from "./cli.js";

// Set the exit code instead of calling process.exit(): writes to a piped stdout
// are asynchronous, and process.exit() would discard whatever is still buffered.
// main() is fully synchronous, so the process ends as soon as it returns.
process.exitCode = main(process.argv.slice(2));

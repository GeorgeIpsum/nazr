import { getThumbmark } from "@nazr/thumbmark";
import { reportFromFrame } from "../frame";

void reportFromFrame({ location, fetch: fetch.bind(globalThis), getThumbmark });

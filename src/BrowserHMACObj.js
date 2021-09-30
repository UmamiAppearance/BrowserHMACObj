import { BaseEx } from "../lib/BaseEx/src/BaseEx.js";
import hmac from "./main.js";

hmac.converters = new BaseEx("bytes");

export default hmac;
import { BaseEx } from "../lib/BaseEx/src/BaseEx.js";
import HMAC from "./main.js";

HMAC.prototype.converters = new BaseEx("bytes");

export default HMAC;
// Disposable separate signing process: not KMS/HSM, not independently isolated.
import {createHmac} from "node:crypto";
const secret=process.env.IB03O_LAB_SECRET;
if(!/^[0-9a-f]{64}$/.test(secret??"")||process.argv.length!==3)process.exit(2);
process.stdout.write(createHmac("sha256",Buffer.from(secret,"hex")).update(process.argv[2]).digest("hex"));

/**
 *
 *
 * @author: Bernhard Lukassen
 */

import util                         from '/util';
import fs                           from '/fs';
import path                         from "/path";
import VaultStore                   from './vaultstore.mjs';

const exists                        = util.promisify(fs.exists);
const stat                          = util.promisify(fs.stat);
const readFile                      = util.promisify(fs.readFile);
const writeFile                     = util.promisify(fs.writeFile);


export default class VaultFileStore extends VaultStore {

    constructor(filename) {
        super();
        this.file = filename;
    }

    async read() {
        try {
            return new String(await readFile(this.file));
        } catch (e) {
            // if missing, new vault is created; file will be created on store
            return "";
        }
    }

    async write(payload) {
        await writeFile(this.file, payload);
    }
}

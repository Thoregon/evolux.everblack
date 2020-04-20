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
        return new String(await readFile(this.file));
    }

    async write(payload) {
        await writeFile(this.file, payload);
    }
}

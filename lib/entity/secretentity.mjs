/**
 * persistent entity
 *
 * @author: Bernhard Lukassen
 * @licence: MIT
 * @see: {@link https://github.com/Thoregon}
 */

export default class SecretEntity {

    constructor({
                    id
                } = {}) {
        Object.assign(this, { id });
    }

}

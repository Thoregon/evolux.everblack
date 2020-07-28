/**
 * allow secure communication between publisher and any user
 *
 * @author: Bernhard Lukassen
 */

import Store from "./store.mjs";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PublicStore extends Store {

}

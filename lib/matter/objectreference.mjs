/**
 *
 *
 * @author: Bernhard Lukassen
 */

export default class ObjectReference {

    static forEncryption(value) {
        // check if value is
        //  - a matter node     -> { #: <soul_of_node> }
        //  - a secure store    -> { #: <soul_of_node>, t͛: <classid> }
        //  - an object/array   -> JSON.stringify
        //  all other just return string representation
        if (value == undefined) return null;        // this check is true for undefined and null!
        if (typeof value === 'string') return value;
        return JSON.stringify(value);   // todo [OPEN]: matter node & secret store
    }

    static fromEncryption(value) {
        // check if is a JSON
        // - check if it has a '#' property referencing a matter node
        // - check if it has a '' property to find the class
        // todo [OPEN]: matter node & secret store
        return (typeof value === 'string')
            ? value.startsWith('{')
               ? JSON.parse(value)
               : value
            : null;
    }
}

exports._reverse = function reverse(map) {
    var res = {};

    Object.keys(map).forEach(function(key) {
        // Convert key to integer if it is stringified
        if ((key | 0) == key)
            key = key | 0;

        var value = map[key];
        res[value] = key;
    });

    return res;
};

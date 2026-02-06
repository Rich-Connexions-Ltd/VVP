/**
 * jQuery JSON Shim
 * Provides $.toJSON and $.evalJSON for Verto.js compatibility
 */
(function($) {
    'use strict';

    // Add $.toJSON if not present
    if (typeof $.toJSON !== 'function') {
        $.toJSON = function(o) {
            return JSON.stringify(o);
        };
    }

    // Add $.evalJSON if not present
    if (typeof $.evalJSON !== 'function') {
        $.evalJSON = function(s) {
            return JSON.parse(s);
        };
    }

    // Add $.secureEvalJSON if not present
    if (typeof $.secureEvalJSON !== 'function') {
        $.secureEvalJSON = function(s) {
            return JSON.parse(s);
        };
    }

    console.log('[jQuery JSON Shim] Loaded - $.toJSON available');
})(jQuery);

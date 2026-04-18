#pragma once

/**
 * @file SeekOrigin.h
 * @brief Defines reference positions used by stream seek operations.
 */

namespace ppp {
    namespace io {
        /**
         * @brief Reference points for computing target seek positions.
         */
        enum SeekOrigin {
            /// <summary>Specifies the beginning of a stream.</summary>
            Begin,
            /// <summary>Specifies the current position within a stream.</summary>
            Current,
            /// <summary>Specifies the end of a stream.</summary>
            End
        };
    }
}

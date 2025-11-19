/**
 * Unit tests for utility functions
 * TOOLS IMPROVEMENT #3: TESTING INFRASTRUCTURE
 */

// Mock utility functions for testing
/**
 *
 */
function debounce(func, wait, immediate = false) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            if (!immediate) {
                func(...args);
            }
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) {
            func(...args);
        }
    };
}

/**
 *
 */
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 *
 */
function escapeHTML(str) {
    if (!str) {
        return '';
    }
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return str.replace(/[&<>"']/g, m => map[m]);
}

describe('Utility Functions', () => {
    describe('debounce', () => {
        test('should debounce function calls', (done) => {
            jest.useFakeTimers();
            let callCount = 0;
            const debouncedFn = debounce(() => {
                callCount++;
            }, 100);

            debouncedFn();
            debouncedFn();
            debouncedFn();

            jest.advanceTimersByTime(150);
            expect(callCount).toBe(1);
            jest.useRealTimers();
            done();
        });
    });

    describe('throttle', () => {
        test('should throttle function calls', (done) => {
            jest.useFakeTimers();
            let callCount = 0;
            const throttledFn = throttle(() => {
                callCount++;
            }, 100);

            throttledFn();
            throttledFn();
            throttledFn();

            jest.advanceTimersByTime(50);
            expect(callCount).toBe(1);
            jest.useRealTimers();
            done();
        });
    });

    describe('escapeHTML', () => {
        test('should escape HTML characters', () => {
            const input = '<script>alert("xss")</script>';
            const output = escapeHTML(input);
            expect(output).not.toContain('<script>');
            expect(output).toContain('&lt;script&gt;');
        });
    });
});


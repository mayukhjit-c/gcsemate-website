/**
 * Unit tests for utility functions
 * TOOLS IMPROVEMENT #3: TESTING INFRASTRUCTURE
 */

describe('Utility Functions', () => {
    describe('debounce', () => {
        test('should debounce function calls', (done) => {
            let callCount = 0;
            const debouncedFn = debounce(() => {
                callCount++;
            }, 100);

            debouncedFn();
            debouncedFn();
            debouncedFn();

            setTimeout(() => {
                expect(callCount).toBe(1);
                done();
            }, 150);
        });
    });

    describe('throttle', () => {
        test('should throttle function calls', (done) => {
            let callCount = 0;
            const throttledFn = throttle(() => {
                callCount++;
            }, 100);

            throttledFn();
            throttledFn();
            throttledFn();

            setTimeout(() => {
                expect(callCount).toBe(1);
                done();
            }, 50);
        });
    });

    describe('escapeHTML', () => {
        test('should escape HTML characters', () => {
            const input = '<script>alert("xss")</script>';
            const output = escapeHTML(input);
            expect(output).not.toContain('<script>');
        });
    });
});


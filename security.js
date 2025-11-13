// GCSEMate Security Layer
// Proudly made using no generative AI
// Copyright © 2024 Mayukhjit Chakraborty. All rights reserved.
// Protected by copyright and trade secret laws.

(function() {
    'use strict';
    
    // Domain verification
    const allowedDomains = ['gcsemate.com', 'www.gcsemate.com', 'localhost', '127.0.0.1', 'gcsemate-dev.web.app', 'gcsemate.web.app'];
    const currentDomain = window.location.hostname;
    
    if (!allowedDomains.some(domain => currentDomain === domain || currentDomain.endsWith(domain))) {
        console.error('%cUNAUTHORIZED ACCESS DETECTED', 'color: red; font-size: 24px; font-weight: bold;');
        console.error('%cThis website is protected by copyright. Unauthorized copying or redistribution is illegal.', 'color: red; font-size: 16px;');
        console.error('%cCopyright © 2024 Mayukhjit Chakraborty. All rights reserved.', 'color: orange; font-size: 14px;');
        document.body.innerHTML = '<div style="display:flex;height:100vh;align-items:center;justify-content:center;flex-direction:column;background:#f0f0f0"><h1 style="color:red;font-size:32px;margin-bottom:20px">Unauthorized Access</h1><p style="font-size:18px;color:#666">This application is protected by copyright.</p><p style="color:#999;margin-top:10px">Copyright © 2024 Mayukhjit Chakraborty</p></div>';
        throw new Error('Unauthorized domain access');
    }
    
    // Anti-debugging techniques
    let devtools = {open: false, orientation: null};
    const threshold = 160;
    
    setInterval(() => {
        if (window.outerHeight - window.innerHeight > threshold || 
            window.outerWidth - window.innerWidth > threshold) {
            if (!devtools.open) {
                devtools.open = true;
                console.clear();
                console.error('%cSTOP!', 'color: red; font-size: 50px; font-weight: bold;');
                console.error('%cThis is a proprietary system. Reverse engineering is prohibited.', 'color: orange; font-size: 16px;');
                console.error('%cCopyright © 2024 Mayukhjit Chakraborty', 'color: red; font-size: 14px;');
            }
        } else {
            devtools.open = false;
        }
    }, 500);
    
    // Detect common debugging methods
    const antiDebug = () => {
        const start = performance.now();
        debugger;
        const end = performance.now();
        if (end - start > 100) {
            console.warn('%cDebugger detected. This application is protected.', 'color: red; font-size: 16px;');
        }
    };
    
    // Run anti-debug periodically
    setInterval(antiDebug, 2000);
    
    // Disable right-click context menu
    document.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        return false;
    });
    
    // Disable common shortcuts
    document.addEventListener('keydown', (e) => {
        // Disable F12
        if (e.key === 'F12') {
            e.preventDefault();
            console.warn('%cDeveloper tools are disabled for security.', 'color: orange; font-size: 14px;');
            return false;
        }
        // Disable Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
        if ((e.ctrlKey && e.shiftKey && e.key === 'I') ||
            (e.ctrlKey && e.shiftKey && e.key === 'J') ||
            (e.ctrlKey && e.shiftKey && e.key === 'C') ||
            (e.ctrlKey && e.key === 'U')) {
            e.preventDefault();
            console.warn('%cThis action is disabled for security.', 'color: orange; font-size: 14px;');
            return false;
        }
        // Disable Ctrl+S (save page)
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            console.warn('%cPage saving is disabled.', 'color: orange; font-size: 14px;');
            return false;
        }
    });
    
    // Console notice
    console.log('%cGCSEMate - GCSE Revision Platform', 'color: #3b82f6; font-size: 20px; font-weight: bold;');
    console.log('%cProudly made using no generative AI', 'color: #10b981; font-size: 14px;');
    console.log('%cCopyright © 2024 Mayukhjit Chakraborty', 'color: #6b7280; font-size: 12px;');
    console.log('%cUnauthorized copying, reproduction, or distribution is strictly prohibited.', 'color: #ef4444; font-size: 12px; font-weight: bold;');
    console.log('%cFor licensing inquiries, please contact: mayukhjit.chakraborty@gmail.com', 'color: #3b82f6; font-size: 12px;');
    
    // Image protection - Add watermark to images
    const watermarkImages = () => {
        const images = document.querySelectorAll('img');
        images.forEach(img => {
            if (!img.dataset.watermarked) {
                img.style.position = 'relative';
                img.oncontextmenu = () => false;
                img.onload = function() {
                    if (!this.dataset.watermarked) {
                        this.dataset.watermarked = 'true';
                    }
                };
            }
        });
    };
    
    // Run watermarking on load
    setTimeout(watermarkImages, 1000);
    
    // Monitor DOM changes
    const observer = new MutationObserver(() => {
        watermarkImages();
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Expose minimal public API
    window.GCSEMateSecurity = {
        domain: currentDomain,
        authorized: true,
        copyright: '© 2024 Mayukhjit Chakraborty',
        notice: 'This software is protected by copyright. Unauthorized use is prohibited.'
    };
    
})();


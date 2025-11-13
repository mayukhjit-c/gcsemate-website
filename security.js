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
    
    // Developer tools and debugging are allowed for learning purposes
    // All anti-debugging code has been removed
    
    // Console notice
    console.log('%cGCSEMate - GCSE Revision Platform', 'color: #3b82f6; font-size: 20px; font-weight: bold;');
    console.log('%cProudly made using no generative AI', 'color: #10b981; font-size: 14px;');
    console.log('%cCopyright © 2024 Mayukhjit Chakraborty', 'color: #6b7280; font-size: 12px;');
    console.log('%cUnauthorized copying, reproduction, or distribution is strictly prohibited.', 'color: #ef4444; font-size: 12px; font-weight: bold;');
    console.log('%cFor licensing inquiries, please contact: mayukhjit.chakraborty@gmail.com', 'color: #3b82f6; font-size: 12px;');
    
    // Image protection removed for learning purposes
    // Images can now be inspected freely
    
    // Expose minimal public API
    window.GCSEMateSecurity = {
        domain: currentDomain,
        authorized: true,
        copyright: '© 2024 Mayukhjit Chakraborty',
        notice: 'This software is protected by copyright. Unauthorized use is prohibited.'
    };
    
})();


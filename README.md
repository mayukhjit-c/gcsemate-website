# GCSEMate - GCSE Revision Platform

**Proudly made using no generative AI** - This entire project was handcrafted with pure JavaScript, HTML, and CSS.

GCSEMate is a comprehensive GCSE revision platform designed to help students efficiently access and organize revision materials. Created by Mayukhjit Chakraborty, the platform provides a streamlined interface for students to browse subjects, access past papers, watch educational videos, read blog posts, and utilize an AI tutor.

## Features

### Subject Dashboard
- Browse organized folders for different GCSE subjects
- Access revision notes, past papers, and study materials
- File preview functionality for supported file types
- Star/favorite important files for quick access
- Search across all files with highlighting

### Video Library
- Curated educational videos organized by subject
- YouTube playlist integration
- Easy-to-browse video categories

### Blog
- Regular blog posts with revision tips and study guides
- Comment system for community engagement
- Searchable blog archive

### AI Tutor
- Interactive AI-powered tutoring
- Get help with GCSE subject questions
- Personalized learning assistance

### Calendar & Activity Tracking
- Track your study sessions
- View daily activity statistics
- Monitor your learning progress

### Admin Dashboard (for administrators)
- User management and analytics
- Content management (blog posts, videos, links)
- System health monitoring
- Maintenance mode control

## Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla JS)
- **Framework**: Custom SPA (Single Page Application)
- **Backend**: Firebase (Auth, Firestore, Storage)
- **External APIs**: 
  - Google Drive API (for file management)
  - Google reCAPTCHA Enterprise (for security)
  - YouTube API (for video playlists)

## File Structure

```
gcsemate-website/
├── index.html          # Main HTML structure
├── styles.css          # All CSS styles and animations
├── app.js              # Main JavaScript application logic
├── firebase.rules      # Firestore security rules
├── functions/           # Cloudflare Serverless Functions
│   └── api/
│       ├── drive-files.js      # Google Drive files API
│       ├── drive-subjects.js   # Google Drive subjects API
│       ├── proxy-drive.js      # Google Drive proxy
│       └── recaptcha-verify.js # reCAPTCHA verification
└── README.md           # This file
```

## Setup & Deployment

### Prerequisites
- Firebase project with Auth, Firestore, and Storage enabled
- Google Drive API access
- reCAPTCHA Enterprise site key
- Cloudflare Pages (for hosting)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/mcinderelle/gcsemate-website.git
   cd gcsemate-website
   ```

2. **Configure Firebase**
   - Create a Firebase project at [Firebase Console](https://console.firebase.google.com)
   - Enable Authentication, Firestore, and Storage
   - Add your web app configuration to `index.html`

3. **Set up Google Drive API**
   - Create a service account in Google Cloud Console
   - Enable Google Drive API
   - Configure the API endpoints in the `functions/api` directory

4. **Configure reCAPTCHA**
   - Set up reCAPTCHA Enterprise
   - Add your site key to `index.html`

5. **Deploy to Cloudflare Pages**
   - Connect your GitHub repository to Cloudflare Pages
   - Set build output directory to root
   - Deploy

## Usage

### For Students

1. **Sign Up/Login**
   - Visit the landing page
   - Create an account or sign in
   - Verify your email

2. **Browse Subjects**
   - Navigate to the Dashboard
   - Select a subject folder
   - Browse and preview files
   - Star important files for quick access

3. **Watch Videos**
   - Go to the Videos section
   - Browse playlists by subject
   - Watch educational content

4. **Read Blog**
   - Visit the Blog section
   - Read revision tips and guides
   - Engage with comments

5. **Use AI Tutor**
   - Access the AI Tutor section
   - Ask questions about GCSE topics
   - Get personalized help

### For Administrators

1. **Access Admin Dashboard**
   - Login with admin credentials
   - Navigate to Admin Dashboard

2. **Manage Users**
   - View all users and their activity
   - Monitor user statistics
   - Handle user issues

3. **Manage Content**
   - Add/edit blog posts
   - Update video playlists
   - Manage useful links

4. **System Management**
   - Check system health
   - Set maintenance mode
   - View analytics

## Security

- Firebase Authentication for user management
- Firestore security rules for data access control
- reCAPTCHA Enterprise for bot protection
- HTTPS enforced via Cloudflare

## Contributing

This is a private repository. For contributions, please contact the repository owner.

## License

Copyright © 2025 Mayukhjit Chakraborty. All rights reserved.

## Support

For issues or questions, please contact: [email protected]

## Acknowledgments

Created with love for GCSE students worldwide to make revision accessible and effective.

## Development Philosophy

This project was **proudly made using no generative AI**. Every line of code was carefully crafted by human hands. No AI assistance was used in the development, design, or implementation of this platform. All features, bug fixes, and optimizations were created through traditional programming practices and creative problem-solving.

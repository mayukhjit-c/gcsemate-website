import React from 'react';
import Header from './components/Header';
import Footer from './components/Footer';

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      
      {/* Main Content */}
      <main className="pt-20 pb-16"> {/* pt-20 accounts for fixed header */}
        <div className="container mx-auto px-4">
          {/* Hero Section */}
          <section className="py-16 text-center">
            <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
              Ace Your GCSEs with <span className="text-blue-600">GCSEMate</span>
            </h1>
            <p className="text-xl text-gray-600 mb-8 max-w-2xl mx-auto">
              Free revision platform with organized notes, past papers, videos, and study guides for all subjects. Perfect for AQA, Edexcel, and OCR exam boards.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-medium transition-colors">
                Get Started
              </button>
              <button className="border border-gray-300 hover:border-gray-400 text-gray-700 px-8 py-3 rounded-lg font-medium transition-colors">
                Browse Subjects
              </button>
            </div>
          </section>

          {/* Features Section */}
          <section className="py-16">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="bg-white p-6 rounded-lg shadow-md">
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                  <i className="fas fa-book text-blue-600 text-xl"></i>
                </div>
                <h3 className="text-xl font-semibold mb-2">Revision Notes</h3>
                <p className="text-gray-600">Comprehensive notes organized by topic and exam board to help you master every concept.</p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-md">
                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                  <i className="fas fa-file-alt text-green-600 text-xl"></i>
                </div>
                <h3 className="text-xl font-semibold mb-2">Past Papers</h3>
                <p className="text-gray-600">Thousands of past papers with mark schemes to practice for your exams.</p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-md">
                <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                  <i className="fas fa-video text-purple-600 text-xl"></i>
                </div>
                <h3 className="text-xl font-semibold mb-2">Video Tutorials</h3>
                <p className="text-gray-600">Expert-led video tutorials that break down complex topics into easy-to-understand concepts.</p>
              </div>
            </div>
          </section>

          {/* Subjects Section */}
          <section className="py-16">
            <h2 className="text-3xl font-bold text-center mb-12">Popular Subjects</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {['Mathematics', 'Biology', 'Chemistry', 'Physics', 'English', 'History', 'Geography', 'Computer Science'].map((subject, index) => (
                <div key={index} className="bg-white p-4 rounded-lg shadow text-center hover:shadow-md transition-shadow cursor-pointer">
                  <h3 className="font-semibold">{subject}</h3>
                </div>
              ))}
            </div>
          </section>
        </div>
      </main>
      
      <Footer />
    </div>
  );
}

export default App

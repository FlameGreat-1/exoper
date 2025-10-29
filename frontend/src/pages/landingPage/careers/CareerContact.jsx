import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Mail, User, MessageSquare, CheckCircle } from 'lucide-react';

const CareerContact = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: ''
  });

  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    // Simulate form submission
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    setIsSubmitting(false);
    setIsSubmitted(true);
  };

  if (isSubmitted) {
    return (
      <div className="min-h-screen bg-[#0a0b14] text-white flex items-center justify-center">
        <div className="max-w-2xl mx-auto px-4 text-center">
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-8 border border-[#2a2a2a]">
            <div className="w-16 h-16 bg-green-600/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <CheckCircle size={32} className="text-green-400" />
            </div>
            <h1 className="text-3xl font-bold mb-4">Message Sent!</h1>
            <p className="text-gray-300 mb-6 leading-relaxed">
              Thank you for reaching out. We've received your message and will get back to you soon.
            </p>
            <p className="text-gray-400 text-sm mb-8">
              We typically respond within 24-48 hours.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link 
                to="/careers/all-positions"
                className="bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium py-3 px-6 rounded-lg transition-all"
              >
                View Open Positions
              </Link>
              <Link 
                to="/"
                className="bg-[#1f1f1f] hover:bg-[#252525] text-white font-medium py-3 px-6 rounded-lg transition-colors border border-[#2a2a2a]"
              >
                Back to Home
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <Link 
          to="/careers/all-positions" 
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm"
        >
          <ArrowLeft size={16} />
          ALL POSITIONS
        </Link>

        <div className="mb-12">
          <h1 className="text-4xl lg:text-5xl font-bold mb-4">
            Get in Touch
          </h1>
          <p className="text-xl text-gray-300 leading-relaxed">
            Don't see the perfect role? We'd love to hear from you anyway.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-8">
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
            <div className="flex items-center gap-3 mb-6">
              <Mail size={20} className="text-purple-400" />
              <h2 className="text-xl font-semibold">Contact Information</h2>
            </div>
            
            <div className="space-y-6">
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-300 mb-2">
                  Full Name *
                </label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  required
                  value={formData.name}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="Enter your full name"
                />
              </div>
              
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                  Email Address *
                </label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  required
                  value={formData.email}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="your.email@example.com"
                />
              </div>
              
              <div>
                <label htmlFor="subject" className="block text-sm font-medium text-gray-300 mb-2">
                  Subject *
                </label>
                <select
                  id="subject"
                  name="subject"
                  required
                  value={formData.subject}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                >
                  <option value="">Select a subject</option>
                  <option value="general-inquiry">General Inquiry</option>
                  <option value="future-opportunities">Future Opportunities</option>
                  <option value="internship">Internship Opportunities</option>
                  <option value="partnership">Partnership</option>
                  <option value="other">Other</option>
                </select>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
            <div className="flex items-center gap-3 mb-6">
              <MessageSquare size={20} className="text-purple-400" />
              <h2 className="text-xl font-semibold">Your Message</h2>
            </div>
            
            <div>
              <label htmlFor="message" className="block text-sm font-medium text-gray-300 mb-2">
                Message *
              </label>
              <textarea
                id="message"
                name="message"
                rows={6}
                required
                value={formData.message}
                onChange={handleInputChange}
                className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all resize-none"
                placeholder="Tell us about yourself, your interests, or what you'd like to discuss..."
              />
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-4 justify-end">
            <Link
              to="/careers/all-positions"
              className="bg-[#1f1f1f] hover:bg-[#252525] text-white font-medium py-3 px-8 rounded-lg transition-colors border border-[#2a2a2a] text-center"
            >
              Cancel
            </Link>
            <button
              type="submit"
              disabled={isSubmitting}
              className="bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 disabled:from-gray-600 disabled:to-gray-500 text-white font-medium py-3 px-8 rounded-lg transition-all disabled:cursor-not-allowed"
            >
              {isSubmitting ? 'Sending...' : 'Send Message'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CareerContact;

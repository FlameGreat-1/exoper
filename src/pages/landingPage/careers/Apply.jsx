import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Upload, FileText, User, Mail, Phone, MapPin, Briefcase, Link as LinkIcon, Github, Linkedin, CheckCircle } from 'lucide-react';

const Apply = () => {
  const [searchParams] = useSearchParams();
  const position = searchParams.get('position') || 'Position';
  
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    location: '',
    linkedinUrl: '',
    githubUrl: '',
    portfolioUrl: '',
    coverLetter: '',
    experience: '',
    availability: '',
    salary: '',
    referral: '',
    resume: null
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

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setFormData(prev => ({
      ...prev,
      resume: file
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
            <h1 className="text-3xl font-bold mb-4">Application Submitted!</h1>
            <p className="text-gray-300 mb-6 leading-relaxed">
              Thank you for your interest in the <span className="text-purple-400 font-medium">{position}</span> position. 
              We've received your application and will review it carefully.
            </p>
            <p className="text-gray-400 text-sm mb-8">
              You should hear back from us within 5-7 business days. We'll reach out via email with next steps.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link 
                to="/careers/all-positions"
                className="bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium py-3 px-6 rounded-lg transition-all"
              >
                View Other Positions
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
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <Link 
          to="/careers/all-positions" 
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm"
        >
          <ArrowLeft size={16} />
          ALL POSITIONS
        </Link>

        <div className="mb-12">
          <h1 className="text-4xl lg:text-5xl font-bold mb-4">
            Apply for {position}
          </h1>
          <p className="text-xl text-gray-300 leading-relaxed">
            We're excited to learn more about you. Please fill out the form below and we'll be in touch soon.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-8">
          {/* Personal Information */}
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
            <div className="flex items-center gap-3 mb-6">
              <User size={20} className="text-purple-400" />
              <h2 className="text-xl font-semibold">Personal Information</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-300 mb-2">
                  First Name *
                </label>
                <input
                  type="text"
                  id="firstName"
                  name="firstName"
                  required
                  value={formData.firstName}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="Enter your first name"
                />
              </div>
              
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-300 mb-2">
                  Last Name *
                </label>
                <input
                  type="text"
                  id="lastName"
                  name="lastName"
                  required
                  value={formData.lastName}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="Enter your last name"
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
                <label htmlFor="phone" className="block text-sm font-medium text-gray-300 mb-2">
                  Phone Number
                </label>
                <input
                  type="tel"
                  id="phone"
                  name="phone"
                  value={formData.phone}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="+1 (555) 123-4567"
                />
              </div>
              
              <div className="md:col-span-2">
                <label htmlFor="location" className="block text-sm font-medium text-gray-300 mb-2">
                  Current Location *
                </label>
                <input
                  type="text"
                  id="location"
                  name="location"
                  required
                  value={formData.location}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="City, Country"
                />
              </div>
            </div>
          </div>

          {/* Professional Links */}
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
            <div className="flex items-center gap-3 mb-6">
              <LinkIcon size={20} className="text-purple-400" />
              <h2 className="text-xl font-semibold">Professional Links</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="linkedinUrl" className="block text-sm font-medium text-gray-300 mb-2">
                  LinkedIn Profile
                </label>
                <div className="relative">
                  <Linkedin size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input
                    type="url"
                    id="linkedinUrl"
                    name="linkedinUrl"
                    value={formData.linkedinUrl}
                    onChange={handleInputChange}
                    className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                    placeholder="https://linkedin.com/in/yourprofile"
                  />
                </div>
              </div>
              
              <div>
                <label htmlFor="githubUrl" className="block text-sm font-medium text-gray-300 mb-2">
                  GitHub Profile
                </label>
                <div className="relative">
                  <Github size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input
                    type="url"
                    id="githubUrl"
                    name="githubUrl"
                    value={formData.githubUrl}
                    onChange={handleInputChange}
                    className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                    placeholder="https://github.com/yourusername"
                  />
                </div>
              </div>
              
              <div className="md:col-span-2">
                <label htmlFor="portfolioUrl" className="block text-sm font-medium text-gray-300 mb-2">
                  Portfolio/Website
                </label>
                <input
                  type="url"
                  id="portfolioUrl"
                  name="portfolioUrl"
                  value={formData.portfolioUrl}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="https://yourportfolio.com"
                />
              </div>
            </div>
          </div>

          {/* Resume Upload */}
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
            <div className="flex items-center gap-3 mb-6">
              <FileText size={20} className="text-purple-400" />
              <h2 className="text-xl font-semibold">Resume</h2>
            </div>
            
            <div className="border-2 border-dashed border-[#2a2a2a] rounded-lg p-8 text-center hover:border-purple-500/50 transition-colors">
              <Upload size={32} className="mx-auto mb-4 text-gray-400" />
              <p className="text-gray-300 mb-2">Upload your resume</p>
              <p className="text-gray-500 text-sm mb-4">PDF, DOC, or DOCX (max 10MB)</p>
              <input
                type="file"
                id="resume"
                name="resume"
                accept=".pdf,.doc,.docx"
                onChange={handleFileChange}
                className="hidden"
              />
              <label
                htmlFor="resume"
                className="inline-block bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 font-medium py-2 px-4 rounded-lg cursor-pointer transition-colors border border-purple-500/30"
              >
                Choose File
              </label>
              {formData.resume && (
                <p className="mt-3 text-green-400 text-sm">
                  ✓ {formData.resume.name}
                </p>
              )}
            </div>
          </div>

          {/* Additional Information */}
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
            <div className="flex items-center gap-3 mb-6">
              <Briefcase size={20} className="text-purple-400" />
              <h2 className="text-xl font-semibold">Additional Information</h2>
            </div>
            
            <div className="space-y-6">
              <div>
                <label htmlFor="experience" className="block text-sm font-medium text-gray-300 mb-2">
                  Years of Experience *
                </label>
                <select
                  id="experience"
                  name="experience"
                  required
                  value={formData.experience}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                >
                  <option value="">Select experience level</option>
                  <option value="0-1">0-1 years</option>
                  <option value="2-3">2-3 years</option>
                  <option value="4-5">4-5 years</option>
                  <option value="6-8">6-8 years</option>
                  <option value="9+">9+ years</option>
                </select>
              </div>
              
              <div>
                <label htmlFor="availability" className="block text-sm font-medium text-gray-300 mb-2">
                  Availability *
                </label>
                <select
                  id="availability"
                  name="availability"
                  required
                  value={formData.availability}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                >
                  <option value="">Select availability</option>
                  <option value="immediate">Immediate</option>
                  <option value="2-weeks">2 weeks notice</option>
                  <option value="1-month">1 month notice</option>
                  <option value="2-months">2+ months</option>
                </select>
              </div>
              
              <div>
                <label htmlFor="salary" className="block text-sm font-medium text-gray-300 mb-2">
                  Expected Salary (USD)
                </label>
                <input
                  type="text"
                  id="salary"
                  name="salary"
                  value={formData.salary}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                  placeholder="e.g., $80,000 - $100,000"
                />
              </div>
              
              <div>
                <label htmlFor="referral" className="block text-sm font-medium text-gray-300 mb-2">
                  How did you hear about us?
                </label>
                <select
                  id="referral"
                  name="referral"
                  value={formData.referral}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
                >
                  <option value="">Select an option</option>
                  <option value="job-board">Job Board</option>
                  <option value="linkedin">LinkedIn</option>
                  <option value="referral">Employee Referral</option>
                  <option value="website">Company Website</option>
                  <option value="social-media">Social Media</option>
                  <option value="other">Other</option>
                </select>
              </div>
              
              <div>
                <label htmlFor="coverLetter" className="block text-sm font-medium text-gray-300 mb-2">
                  Cover Letter / Why are you interested in this role?
                </label>
                <textarea
                  id="coverLetter"
                  name="coverLetter"
                  rows={6}
                  value={formData.coverLetter}
                  onChange={handleInputChange}
                  className="w-full bg-[#1f1f1f] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all resize-none"
                  placeholder="Tell us about yourself, your experience, and why you're excited about this opportunity..."
                />
              </div>
            </div>
          </div>

          {/* Submit Button */}
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
              {isSubmitting ? 'Submitting...' : 'Submit Application'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Apply;

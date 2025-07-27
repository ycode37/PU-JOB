// import React, { useContext, useState } from "react";
// import { AppContext } from "../../context/AppContext";

// const Postjob = () => {
//   const { setcompanyData, companyData, navigate } = useContext(AppContext);
//   const [preview, setpreview] = useState(null);
//   const handlefilechange = (e) => {
//     const selectedFile = e.target.files[0];
//     setcompanyData({ ...companyData, logo: selectedFile });
//     if (selectedFile) {
//       const imageURL = URL.createObjectURL(selectedFile);
//       setpreview(imageURL);
//     }
//   };
//   const handleChange = (e) => {
//     setcompanyData({ ...companyData, [e.target.name]: [e.target.value] });
//   };
//   const handleSubmit = async (e) => {
//     e.preventDefault();
//     navigate("/employer/jobs-list");
//   };
//   const [jobData, setjobData] = useState({
//     title: "",
//     company: "",
//     description: "",
//     location: "",
//     salary: "",
//     type: "",
//     image: null,
//     requirements: "",
//     benefits: "",
//     jobLevel: "",
//     education: "",
//     experience: "",
//   });

//   return (
//     <div>
//       <form
//         action="
//       "
//       >
//         <h2>Put a New Job</h2>
//         {preview && (
//           <div>
//             <img src={preview} alt="" />
//           </div>
//         )}
//         <div>
//           <input
//             type="file"
//             accept="image/*"
//             onChange={handlefilechange}
//             name="image"
//           />
//         </div>
//       </form>
//       <label htmlFor="job-title">Job Title</label>
//       <input
//         type="text"
//         name="title"
//         value={jobData.title}
//         onChange={handleChange}
//         placeholder="Enter Job Title."
//         required
//       />
//       <label htmlFor="company-name">Company Name</label>
//       <input
//         type="text"
//         name="title"
//         value={jobData.company}
//         onChange={handleChange}
//         placeholder="Enter Job Title."
//         required
//       />
//       <label htmlFor="job-description">Job Description</label>
//       <textarea
//         type="text"
//         name="title"
//         value={jobData.description}
//         onChange={handleChange}
//         placeholder="Enter Job Title."
//         required
//       ></textarea>
//       <label htmlFor="job-location">Job Location</label>
//       <input
//         type="text"
//         name="location"
//         value={jobData.location}
//         onChange={handleChange}
//         placeholder="Enter Job Title."
//         required
//       />
//       <label htmlFor="">Job type</label>
//       <select name="type" value={jobData.type} onChange={handleChange} id="">
//         <option value="">Select Type</option>
//         <option value="Full-time">FullTime</option>
//         <option value="Part-time">PartTime</option>
//         <option value="Remote">Remote</option>
//         <option value="Intership">Internship</option>
//       </select>
//       <label htmlFor="">Requirements</label>
//       <textarea
//         name="requirements"
//         value={jobData.requirements}
//         onChange={handleChange}
//         rows="2"
//         placeholder="sepreate with commas"
//         id=""
//       ></textarea>
//       <label htmlFor="education">Education</label>
//       <input
//         type="text"
//         name="education"
//         value={jobData.education}
//         onChange={handleChange}
//         placeholder="Enter Job Title."
//         required
//       />
//       <label htmlFor="experience">Experience</label>
//       <input
//         type="text"
//         name="experience"
//         value={jobData.experience}
//         onChange={handleChange}
//         placeholder="Enter Job Title."
//         required
//       />
//     </div>
//   );
// };

// export default Postjob;

import React, { useContext, useState } from "react";
import { AppContext } from "../../context/AppContext";

const Postjob = () => {
  const { setcompanyData, companyData, navigate } = useContext(AppContext);
  const [preview, setpreview] = useState(null);

  const [jobData, setjobData] = useState({
    title: "",
    company: "",
    description: "",
    location: "",
    salary: "",
    type: "",
    image: null,
    requirements: "",
    benefits: "",
    jobLevel: "",
    education: "",
    experience: "",
  });

  const handlefilechange = (e) => {
    const selectedFile = e.target.files[0];
    setjobData({ ...jobData, image: selectedFile });
    if (selectedFile) {
      const imageURL = URL.createObjectURL(selectedFile);
      setpreview(imageURL);
    }
  };

  const handleChange = (e) => {
    setjobData({ ...jobData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    navigate("/employer/jobs-list");
  };

  return (
    <div className="max-w-4xl mx-auto mt-6 p-6">
      <div className="bg-white shadow-sm rounded-lg overflow-hidden">
        {/* Header */}
        <div className="bg-gray-50 px-6 py-4 border-b border-gray-200">
          <h2 className="text-2xl font-semibold text-gray-800">
            Post a New Job
          </h2>
          <p className="text-gray-600 mt-1">
            Fill in the details to create a new job posting
          </p>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Job Image Upload */}
          <div className="space-y-4">
            <label className="block text-sm font-medium text-gray-700">
              Job Image
            </label>

            <div className="flex items-center space-x-6">
              <div className="flex-shrink-0">
                {preview ? (
                  <img
                    src={preview}
                    alt="Job image preview"
                    className="w-24 h-24 object-cover rounded-lg border-2 border-gray-200 shadow-sm"
                  />
                ) : (
                  <div className="w-24 h-24 bg-gray-100 rounded-lg border-2 border-dashed border-gray-300 flex items-center justify-center">
                    <svg
                      className="w-8 h-8 text-gray-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"
                      />
                    </svg>
                  </div>
                )}
              </div>

              <div className="flex-1">
                <label className="relative cursor-pointer bg-white rounded-lg border border-gray-300 py-3 px-4 flex items-center justify-center hover:bg-gray-50 focus-within:ring-2 focus-within:ring-blue-500 focus-within:border-transparent transition-colors duration-200">
                  <div className="text-center">
                    <svg
                      className="mx-auto h-8 w-8 text-gray-400 mb-2"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                      />
                    </svg>
                    <span className="text-sm font-medium text-gray-700">
                      {preview ? "Change Image" : "Upload Image"}
                    </span>
                    <p className="text-xs text-gray-500 mt-1">
                      PNG, JPG up to 10MB
                    </p>
                  </div>
                  <input
                    type="file"
                    className="sr-only"
                    accept="image/*"
                    onChange={handlefilechange}
                    name="image"
                  />
                </label>
              </div>
            </div>
          </div>

          {/* Basic Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label
                htmlFor="title"
                className="block text-sm font-medium text-gray-700"
              >
                Job Title *
              </label>
              <input
                type="text"
                id="title"
                name="title"
                value={jobData.title}
                onChange={handleChange}
                placeholder="e.g. Senior Software Developer"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                required
              />
            </div>

            <div className="space-y-2">
              <label
                htmlFor="company"
                className="block text-sm font-medium text-gray-700"
              >
                Company Name *
              </label>
              <input
                type="text"
                id="company"
                name="company"
                value={jobData.company}
                onChange={handleChange}
                placeholder="Enter company name"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                required
              />
            </div>
          </div>

          {/* Location and Salary */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label
                htmlFor="location"
                className="block text-sm font-medium text-gray-700"
              >
                Job Location *
              </label>
              <input
                type="text"
                id="location"
                name="location"
                value={jobData.location}
                onChange={handleChange}
                placeholder="e.g. New York, NY or Remote"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                required
              />
            </div>

            <div className="space-y-2">
              <label
                htmlFor="salary"
                className="block text-sm font-medium text-gray-700"
              >
                Salary Range
              </label>
              <input
                type="text"
                id="salary"
                name="salary"
                value={jobData.salary}
                onChange={handleChange}
                placeholder="e.g. $80,000 - $120,000"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
              />
            </div>
          </div>

          {/* Job Type and Level */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label
                htmlFor="type"
                className="block text-sm font-medium text-gray-700"
              >
                Job Type *
              </label>
              <select
                id="type"
                name="type"
                value={jobData.type}
                onChange={handleChange}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                required
              >
                <option value="">Select Job Type</option>
                <option value="Full-time">Full-time</option>
                <option value="Part-time">Part-time</option>
                <option value="Remote">Remote</option>
                <option value="Internship">Internship</option>
                <option value="Contract">Contract</option>
              </select>
            </div>

            <div className="space-y-2">
              <label
                htmlFor="jobLevel"
                className="block text-sm font-medium text-gray-700"
              >
                Job Level
              </label>
              <select
                id="jobLevel"
                name="jobLevel"
                value={jobData.jobLevel}
                onChange={handleChange}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
              >
                <option value="">Select Level</option>
                <option value="Entry Level">Entry Level</option>
                <option value="Mid Level">Mid Level</option>
                <option value="Senior Level">Senior Level</option>
                <option value="Executive">Executive</option>
              </select>
            </div>
          </div>

          {/* Education and Experience */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label
                htmlFor="education"
                className="block text-sm font-medium text-gray-700"
              >
                Education Required *
              </label>
              <input
                type="text"
                id="education"
                name="education"
                value={jobData.education}
                onChange={handleChange}
                placeholder="e.g. Bachelor's in Computer Science"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                required
              />
            </div>

            <div className="space-y-2">
              <label
                htmlFor="experience"
                className="block text-sm font-medium text-gray-700"
              >
                Experience Required *
              </label>
              <input
                type="text"
                id="experience"
                name="experience"
                value={jobData.experience}
                onChange={handleChange}
                placeholder="e.g. 3-5 years"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                required
              />
            </div>
          </div>

          {/* Job Description */}
          <div className="space-y-2">
            <label
              htmlFor="description"
              className="block text-sm font-medium text-gray-700"
            >
              Job Description *
            </label>
            <textarea
              id="description"
              name="description"
              value={jobData.description}
              onChange={handleChange}
              rows={6}
              placeholder="Describe the role, responsibilities, and what the candidate will be doing..."
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200 resize-vertical"
              required
            />
          </div>

          {/* Requirements */}
          <div className="space-y-2">
            <label
              htmlFor="requirements"
              className="block text-sm font-medium text-gray-700"
            >
              Requirements
            </label>
            <textarea
              id="requirements"
              name="requirements"
              value={jobData.requirements}
              onChange={handleChange}
              rows={4}
              placeholder="List the key requirements, skills, and qualifications (separate with commas)"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200 resize-vertical"
            />
            <p className="text-xs text-gray-500">
              Separate multiple requirements with commas
            </p>
          </div>

          {/* Benefits */}
          <div className="space-y-2">
            <label
              htmlFor="benefits"
              className="block text-sm font-medium text-gray-700"
            >
              Benefits & Perks
            </label>
            <textarea
              id="benefits"
              name="benefits"
              value={jobData.benefits}
              onChange={handleChange}
              rows={4}
              placeholder="List the benefits, perks, and what makes this role attractive (separate with commas)"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200 resize-vertical"
            />
            <p className="text-xs text-gray-500">
              e.g. Health insurance, Flexible hours, Remote work, etc.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-3 pt-6 border-t border-gray-200">
            <button
              type="button"
              onClick={() => navigate("/employer/jobs-list")}
              className="flex-1 sm:flex-none px-6 py-3 border border-gray-300 text-gray-700 bg-white rounded-lg hover:bg-gray-50 font-medium transition-colors duration-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 sm:flex-none px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium transition-colors duration-200 shadow-sm"
            >
              Post Job
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Postjob;

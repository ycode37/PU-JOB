import React, { useContext } from "react";
import { AppContext } from "../context/AppContext";
import { useParams } from "react-router-dom";
import { assets } from "../assets/assets";
import toast from "react-hot-toast";

const Jobdetail = () => {
  const { jobsData, isJobapplied, setisJobapplied, savedJob, savedJobs } =
    useContext(AppContext);
  const { id } = useParams();
  const job = jobsData.find((job) => job._id === parseInt(id));

  if (!job) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl md:text-4xl font-bold text-gray-900 mb-2">
            Job Details
          </h1>
          <div className="w-24 h-1 bg-blue-600 mx-auto rounded-full"></div>
        </div>

        {/* Main Job Card */}
        <div className="bg-white rounded-2xl shadow-lg overflow-hidden mb-6">
          {/* Job Header */}
          <div className="bg-gradient-to-r from-blue-600 to-purple-600 p-6 text-white">
            <div className="flex flex-col md:flex-row items-center gap-6">
              <div className="flex-shrink-0">
                <img
                  src={job.image}
                  alt={job.company}
                  className="w-20 h-20 rounded-xl bg-white p-2 shadow-lg"
                />
              </div>
              <div className="text-center md:text-left flex-grow">
                <h2 className="text-2xl md:text-3xl font-bold mb-2">
                  {job.title}
                </h2>
                <div className="flex flex-col sm:flex-row items-center gap-3">
                  <p className="text-lg opacity-90">{job.company}</p>
                  <span className="bg-white/20 backdrop-blur-sm px-3 py-1 rounded-full text-sm font-medium">
                    {job.type}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Job Content */}
          <div className="p-6 space-y-8">
            {/* Description */}
            <section>
              <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                <div className="w-1 h-6 bg-blue-600 rounded-full mr-3"></div>
                Job Description
              </h3>
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-gray-700 leading-relaxed">
                  {job.description}
                </p>
              </div>
            </section>

            {/* Requirements & Benefits Grid */}
            <div className="grid md:grid-cols-2 gap-6">
              {/* Requirements */}
              <section>
                <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                  <div className="w-1 h-6 bg-green-600 rounded-full mr-3"></div>
                  Requirements
                </h3>
                <div className="bg-green-50 rounded-lg p-4">
                  <ul className="space-y-2">
                    {job.requirements.map((item, index) => (
                      <li key={index} className="flex items-start">
                        <span className="flex-shrink-0 w-2 h-2 bg-green-600 rounded-full mt-2 mr-3"></span>
                        <span className="text-gray-700">{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </section>

              {/* Benefits */}
              <section>
                <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                  <div className="w-1 h-6 bg-purple-600 rounded-full mr-3"></div>
                  Benefits
                </h3>
                <div className="bg-purple-50 rounded-lg p-4">
                  <ul className="space-y-2">
                    {job.benefits.map((item, index) => (
                      <li key={index} className="flex items-start">
                        <span className="flex-shrink-0 w-2 h-2 bg-purple-600 rounded-full mt-2 mr-3"></span>
                        <span className="text-gray-700">{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </section>
            </div>
          </div>
        </div>

        {/* Action Section */}
        <div className="bg-white rounded-2xl shadow-lg p-6 mb-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <button
                onClick={() => savedJob(job)}
                className="p-3 border-2 border-gray-300 rounded-xl hover:border-blue-600 hover:bg-blue-50 transition-all duration-200"
              >
                <img
                  src={assets.save_later_icon}
                  alt="Save"
                  className="w-6 h-6"
                />
              </button>
              <button
                onClick={() => {
                  setisJobapplied(!isJobapplied);
                  toast.success("Job Applied Succefully");
                }}
                disabled={isJobapplied}
                className="px-8 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-xl hover:shadow-lg transform hover:scale-105 transition-all duration-200"
              >
                {isJobapplied ? "Applied" : "Apply Now"}
              </button>
            </div>

            <div className="flex items-center gap-6 text-sm text-gray-600">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Actively hiring</span>
              </div>
            </div>
          </div>
        </div>

        {/* Job Details Cards */}
        <div className="grid md:grid-cols-2 gap-6">
          {/* Salary & Location */}
          <div className="bg-white rounded-2xl shadow-lg p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Compensation & Location
            </h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                <span className="text-gray-600">Salary</span>
                <span className="font-semibold text-green-700">
                  {job.salary}
                </span>
              </div>
              <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                <span className="text-gray-600">Location</span>
                <span className="font-semibold text-blue-700">
                  {job.location}
                </span>
              </div>
            </div>
          </div>

          {/* Job Overview */}
          <div className="bg-white rounded-2xl shadow-lg p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Job Overview
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500 uppercase tracking-wide">
                  Posted
                </p>
                <p className="font-semibold text-gray-900">{job.postedDate}</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500 uppercase tracking-wide">
                  Level
                </p>
                <p className="font-semibold text-gray-900">{job.level}</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500 uppercase tracking-wide">
                  Education
                </p>
                <p className="font-semibold text-gray-900">{job.education}</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500 uppercase tracking-wide">
                  Experience
                </p>
                <p className="font-semibold text-gray-900">{job.experience}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Jobdetail;

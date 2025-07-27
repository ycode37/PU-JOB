// import React, { useContext, useState } from "react";
// import { AppContext } from "../../context/AppContext";

// export const Addcompany = () => {
//   const { navigate } = useContext(AppContext);
//   const [companyData, setcompanyData] = useState({
//     name: "",
//     about: "",
//     logo: null,
//   });
//   const [preview, setpreview] = useState(null);
//   const [file, setfile] = useState(null);
//   const handleChange = (e) => {
//     setcompanyData({ ...companyData, [e.target.name]: [e.target.value] });
//   };
//   const handlefilechange = (e) => {
//     const selectedFile = e.target.files[0];
//     setcompanyData({ ...companyData, logo: selectedFile });
//     if (selectedFile) {
//       const imageURL = URL.createObjectURL(selectedFile);
//       setpreview(imageURL);
//     }
//   };
//   const handleSubmit = async (e) => {
//     e.preventDefault();
//     navigate("/employer");
//   };

//   return (
//     <div className="flex items-center max-w-4xl w-full mx-auto">
//       <form
//         onSubmit={handleSubmit}
//         className="bg-white text-gray-500 max-w-96 mx-4 md:p-6 p-4 text-left text-s rounded shadow-[0px_0px_10px_0px] shadow-black/10"
//       >
//         <h2 className="text-2xl font-medium text-gray-800">
//           Register A new Company
//         </h2>
//         <div>
//           {preview && (
//             <div className="mb-3 flex justify-center">
//               <img
//                 src={preview}
//                 alt=""
//                 className="w-24 h-24 object-cover rounded-full border shadow"
//               />
//             </div>
//           )}
//           <input
//             type="file"
//             accept="image/*"
//             onChange={handlefilechange}
//             className="block w-full text-sm text-gray-500
// file:mr-4 file:py-2 file:px-4
// file: rounded-full file:border-0 file: text-sm file: font-semibold
// file: bg-blue-50
// file: text-blue-700
// hover: file: bg-blue-100 cursor-pointer"
//           />
//         </div>
//         <label htmlFor="name">Company Name</label>
//         <input
//           type="text"
//           value={companyData.name}
//           onChange={handleChange}
//           name="name"
//           placeholder="Name"
//           className="w-full border mt-1 border-gray-500/30 focus:border-indigo-500 outline-none rounded py-2.5 px-4"
//         />
//         <div className="mb-4">
//           <label htmlFor="about">About</label>
//           <textarea
//             name="about"
//             rows="4"
//             value={companyData.about}
//             onChange={handleChange}
//             placeholder="Enter About"
//             className="w-full border mt-1 border-gray-500/30 focus:border-indigo-500 outline-none rounded py-2.5 px-4"
//           ></textarea>
//         </div>
//         <button type="submit">Add company</button>
//       </form>
//     </div>
//   );
// };

import React, { useContext, useState } from "react";
import { AppContext } from "../../context/AppContext";

export const Addcompany = () => {
  const { navigate } = useContext(AppContext);
  const [companyData, setcompanyData] = useState({
    name: "",
    about: "",
    logo: null,
  });
  const [preview, setpreview] = useState(null);
  const [file, setfile] = useState(null);

  const handleChange = (e) => {
    setcompanyData({ ...companyData, [e.target.name]: [e.target.value] });
  };

  const handlefilechange = (e) => {
    const selectedFile = e.target.files[0];
    setcompanyData({ ...companyData, logo: selectedFile });
    if (selectedFile) {
      const imageURL = URL.createObjectURL(selectedFile);
      setpreview(imageURL);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    navigate("/employer");
  };

  return (
    <div className="max-w-4xl mx-auto mt-6 p-6">
      <div className="bg-white shadow-sm rounded-lg overflow-hidden">
        {/* Header */}
        <div className="bg-gray-50 px-6 py-4 border-b border-gray-200">
          <h1 className="text-2xl font-semibold text-gray-800">
            Register A New Company
          </h1>
          <p className="text-gray-600 mt-1">
            Add your company details to get started
          </p>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Logo Upload Section */}
          <div className="space-y-4">
            <label className="block text-sm font-medium text-gray-700">
              Company Logo
            </label>

            <div className="flex items-center space-x-6">
              <div className="flex-shrink-0">
                {preview ? (
                  <img
                    src={preview}
                    alt="Company logo preview"
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
                      {preview ? "Change Logo" : "Upload Logo"}
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
                  />
                </label>
              </div>
            </div>
          </div>

          {/* Company Name */}
          <div className="space-y-2">
            <label
              htmlFor="name"
              className="block text-sm font-medium text-gray-700"
            >
              Company Name *
            </label>
            <input
              type="text"
              id="name"
              name="name"
              value={companyData.name}
              onChange={handleChange}
              placeholder="Enter your company name"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
              required
            />
          </div>

          {/* About Company */}
          <div className="space-y-2">
            <label
              htmlFor="about"
              className="block text-sm font-medium text-gray-700"
            >
              About Company *
            </label>
            <textarea
              id="about"
              name="about"
              value={companyData.about}
              onChange={handleChange}
              rows={5}
              placeholder="Tell us about your company, its mission, values, and what makes it unique..."
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200 resize-vertical"
              required
            />
            <p className="text-xs text-gray-500">
              Minimum 50 characters recommended
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-3 pt-6 border-t border-gray-200">
            <button
              type="button"
              onClick={() => navigate("/employer")}
              className="flex-1 sm:flex-none px-6 py-3 border border-gray-300 text-gray-700 bg-white rounded-lg hover:bg-gray-50 font-medium transition-colors duration-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 sm:flex-none px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium transition-colors duration-200 shadow-sm"
            >
              Add Company
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

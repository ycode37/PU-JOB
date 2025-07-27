// import React, { useContext } from "react";
// import { AppContext } from "../../context/AppContext";
// import toast from "react-hot-toast";

// const Companieslist = () => {
//   const { navigate, companyData, setcompanyData } = useContext(AppContext);
//   const handledelete = (id) => {
//     const updatedCompanies = companyData.filter(
//       (company) => company._id !== id
//     );
//     setcompanyData(updatedCompanies);
//     toast.success("Company Deleted Successfully");
//   };
//   console.log(companyData);

//   return (
//     <div className="max-w-5xl mx-auto mt-10 bg-white shadow rounded-lg ">
//       <div className="flex items-center justify-between mb-6">
//         <h2 className="text-2xl md:text-4xl font-medium text-gray-800">
//           Company List
//         </h2>
//         <button
//           onClick={() => navigate("/employer/add-company")}
//           className="bg-primary text-white px-4 py-2 rounded bg-blue-700 cursor-pointer"
//         >
//           Add Company
//         </button>
//       </div>
//       <table className="w-full px-6 border border-gray-300 rounded overflow-hidden">
//         <thead className="bg-gray-50">
//           <tr>
//             <th className="text-left border-b p-3">Logo</th>
//             <th className="text-left border-b p-3">Name</th>
//             <th className="text-left border-b p-3">About</th>
//             <th className="text-left border-b p-3">Delete</th>
//           </tr>
//         </thead>
//         <tbody className="divide-y divide-gray-300">
//           {companyData.map((company) => (
//             <tr key={company._id} className="hover:bg-gray-50">
//               <td className="p-3 border-b">
//                 <img
//                   src={company.logo}
//                   alt=""
//                   className="w-16 h-16 object-cover border"
//                 />
//               </td>
//               <td className="p-3 border-b">
//                 <p>{company.name}</p>
//               </td>
//               <td className="p-3 border-b">
//                 <p>{company.about}</p>
//               </td>
//               <td className="p-3 border-b">
//                 <button
//                   onClick={() => handledelete(company._id)}
//                   className="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600"
//                 >
//                   Delete
//                 </button>
//               </td>
//             </tr>
//           ))}
//         </tbody>
//       </table>
//     </div>
//   );
// };

// export default Companieslist;

import React, { useContext, useState } from "react";
import { AppContext } from "../../context/AppContext";
import toast from "react-hot-toast";

const Companieslist = () => {
  const { navigate, companyData, setcompanyData } = useContext(AppContext);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Filter companies based on search term
  const filteredCompanies = companyData.filter(
    (company) =>
      company.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      company.about.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDelete = async (id, companyName) => {
    setIsLoading(true);
    try {
      const updatedCompanies = companyData.filter(
        (company) => company._id !== id
      );
      setcompanyData(updatedCompanies);
      toast.success(`${companyName} deleted successfully`);
    } catch (error) {
      toast.error("Failed to delete company");
    } finally {
      setIsLoading(false);
      setDeleteConfirm(null);
    }
  };

  const confirmDelete = (company) => {
    setDeleteConfirm(company);
  };

  const cancelDelete = () => {
    setDeleteConfirm(null);
  };

  return (
    <div className="max-w-6xl mx-auto mt-6 p-4">
      {/* Header Section */}
      <div className="bg-white shadow-sm rounded-lg p-6 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-2xl md:text-3xl font-semibold text-gray-800">
              Company Management
            </h2>
            <p className="text-gray-600 mt-1">
              Manage your companies ({filteredCompanies.length} of{" "}
              {companyData.length})
            </p>
          </div>
          <button
            onClick={() => navigate("/employer/add-company")}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors duration-200 flex items-center gap-2"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 4v16m8-8H4"
              />
            </svg>
            Add Company
          </button>
        </div>

        {/* Search Bar */}
        <div className="mt-4">
          <div className="relative">
            <svg
              className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            <input
              type="text"
              placeholder="Search companies by name or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm("")}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Companies List */}
      <div className="bg-white shadow-sm rounded-lg overflow-hidden">
        {filteredCompanies.length === 0 ? (
          <div className="text-center py-12">
            <svg
              className="mx-auto w-16 h-16 text-gray-300 mb-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1}
                d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"
              />
            </svg>
            <h3 className="text-lg font-medium text-gray-800 mb-2">
              {companyData.length === 0
                ? "No companies yet"
                : "No companies found"}
            </h3>
            <p className="text-gray-600 mb-4">
              {companyData.length === 0
                ? "Get started by adding your first company"
                : "Try adjusting your search terms"}
            </p>
            {companyData.length === 0 && (
              <button
                onClick={() => navigate("/employer/add-company")}
                className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors duration-200"
              >
                Add Your First Company
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left p-4 font-semibold text-gray-700">
                    Company
                  </th>
                  <th className="text-left p-4 font-semibold text-gray-700 hidden md:table-cell">
                    About
                  </th>
                  <th className="text-right p-4 font-semibold text-gray-700">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {filteredCompanies.map((company) => (
                  <tr
                    key={company._id}
                    className="hover:bg-gray-50 transition-colors duration-150"
                  >
                    <td className="p-4">
                      <div className="flex items-center gap-4">
                        <div className="flex-shrink-0">
                          <img
                            src={company.logo}
                            alt={`${company.name} logo`}
                            className="w-12 h-12 rounded-lg object-cover border border-gray-200"
                            onError={(e) => {
                              e.target.src = "/placeholder-company-logo.png"; // Fallback image
                            }}
                          />
                        </div>
                        <div>
                          <h3 className="font-medium text-gray-900">
                            {company.name}
                          </h3>
                          <p className="text-sm text-gray-500 md:hidden">
                            {company.about?.slice(0, 50)}...
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="p-4 hidden md:table-cell">
                      <p className="text-gray-700 max-w-md">
                        {company.about?.slice(0, 100)}
                        {company.about?.length > 100 && "..."}
                      </p>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => confirmDelete(company)}
                          className="text-red-600 hover:text-red-800 hover:bg-red-50 p-2 rounded-lg transition-colors duration-200"
                          title="Delete company"
                          disabled={isLoading}
                        >
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                            />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg max-w-md w-full p-6">
            <div className="flex items-center gap-4 mb-4">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                  <svg
                    className="w-6 h-6 text-red-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                    />
                  </svg>
                </div>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">
                  Delete Company
                </h3>
                <p className="text-gray-600">
                  Are you sure you want to delete "{deleteConfirm.name}"? This
                  action cannot be undone.
                </p>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={cancelDelete}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg font-medium transition-colors duration-200"
                disabled={isLoading}
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  handleDelete(deleteConfirm._id, deleteConfirm.name)
                }
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors duration-200 disabled:opacity-50"
                disabled={isLoading}
              >
                {isLoading ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Companieslist;

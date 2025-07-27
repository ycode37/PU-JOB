// import { AppContext } from "../../context/AppContext";
// import toast from "react-hot-toast";
// import { useContext } from "react";
// import { assets } from "../../assets/assets";
// import { Link, Outlet, useLocation } from "react-router-dom";

// const Employerlayout = () => {
//   const { navigate, setemployer } = useContext(AppContext);
//   const location = useLocation();

//   const sidebarLinks = [
//     { name: "Companies", path: "/employer" },
//     { name: "Add Company", path: "/employer/add-company" },
//     { name: "Jobs", path: "/employer/jobs-list" },
//     { name: "post job", path: "/employer/post-job" },
//     { name: "Applicants", path: "/employer/applicants" },
//   ];

//   const isActive = (path) => {
//     if (path === "/employer") {
//       return location.pathname === "/employer";
//     }
//     return location.pathname === path;
//   };

//   return (
//     <>
//       <div className="flex items-center justify-between px-4 md:px-8 border-b border-gray-300 py-3 bg-white transition-all duration-300">
//         <Link to={"/employer"}>
//           <img src={assets.logo} alt="" className="w-20 m-0" />
//         </Link>
//         <div className="flex items-center gap-5 text-gray-500">
//           <p>Hi! Employer</p>
//           <button
//             onClick={() => {
//               setemployer(false);
//               navigate("/");
//               toast.success("Logged Out Successfully");
//             }}
//             className="border rounded-full text-sm px-4 py-1 hover:bg-gray-50 transition-colors duration-200"
//           >
//             Logout
//           </button>
//         </div>
//       </div>

//       <div className="flex">
//         <div className="md:w-64 w-16 border-r h-[550px] text-base border-gray-300 pt-4 flex flex-col transition-all duration-300">
//           {sidebarLinks.map((item, index) => (
//             <Link
//               to={item.path}
//               key={index}
//               className={`flex items-center py-3 px-4 gap-3 transition-all duration-200
//                 ${
//                   isActive(item.path)
//                     ? "border-r-4 md:border-r-[6px] bg-indigo-500/10 border-indigo-500 text-indigo-500"
//                     : "hover:bg-gray-100/90 border-white text-gray-700 hover:text-gray-900"
//                 }`}
//             >
//               <p className="md:block hidden text-center">{item.name}</p>
//             </Link>
//           ))}
//         </div>
//         <Outlet />
//       </div>
//     </>
//   );
// };

// export default Employerlayout;

import { AppContext } from "../../context/AppContext";
import toast from "react-hot-toast";
import { useContext, useState } from "react";
import { assets } from "../../assets/assets";
import { Link, Outlet, useLocation } from "react-router-dom";

const Employerlayout = () => {
  const { navigate, setemployer, axios, setuser, employer } =
    useContext(AppContext);
  const location = useLocation();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const sidebarLinks = [
    { name: "Companies", path: "/employer" },
    { name: "Add Company", path: "/employer/add-company" },
    { name: "Jobs", path: "/employer/jobs-list" },
    { name: "post job", path: "/employer/post-job" },
    { name: "Applicants", path: "/employer/applicants" },
  ];

  const isActive = (path) => {
    if (path === "/employer") {
      return location.pathname === "/employer";
    }
    return location.pathname === path;
  };

  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };
  const logout = async () => {
    try {
      const { data } = await axios.get(`${import.meta.env.VITE_MY_URL}/auth/logout`, {
        withCredentials: true,
      });
      setuser(false);
      setemployer(false);
      navigate("/");
      toast.success(data.message);
    } catch (error) {
      toast.error(error?.response?.data?.message || "Logout failed");
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 sm:px-6 md:px-8 border-b border-gray-300 py-3 bg-white">
        <div className="flex items-center gap-4">
          <button
            className="md:hidden p-2"
            onClick={toggleSidebar}
            aria-label="Toggle sidebar"
          >
            <svg
              className="w-6 h-6"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 6h16M4 12h16M4 18h16"
              />
            </svg>
          </button>
          <Link to={"/employer"}>
            <img src={assets.logo} alt="Logo" className="w-16 sm:w-20" />
          </Link>
        </div>
        <div className="flex items-center gap-3 sm:gap-5 text-gray-500 text-sm sm:text-base">
          <p className="hidden sm:block">Hi! Employer</p>
          <button
            onClick={logout}
            className="border rounded-full text-xs sm:text-sm px-3 sm:px-4 py-1 hover:bg-gray-50 transition-colors duration-200"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <div
          className={`fixed md:static inset-y-0 left-0 z-50 w-56 md:w-64 bg-white border-r border-gray-300 pt-4 flex flex-col transition-transform duration-300 transform ${
            isSidebarOpen
              ? "translate-x-0"
              : "-translate-x-full md:translate-x-0"
          }`}
        >
          <div className="flex justify-end md:hidden p-2">
            <button onClick={toggleSidebar} aria-label="Close sidebar">
              <svg
                className="w-6 h-6"
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
          </div>
          {sidebarLinks.map((item, index) => (
            <Link
              to={item.path}
              key={index}
              onClick={() => setIsSidebarOpen(false)}
              className={`flex items-center py-3 px-4 gap-3 transition-all duration-200 ${
                isActive(item.path)
                  ? "border-r-4 md:border-r-[6px] bg-indigo-500/10 border-indigo-500 text-indigo-500"
                  : "hover:bg-gray-100/90 border-white text-gray-700 hover:text-gray-900"
              }`}
            >
              <p className="text-sm md:text-base">{item.name}</p>
            </Link>
          ))}
        </div>

        {/* Overlay for mobile when sidebar is open */}
        {isSidebarOpen && (
          <div
            className="fixed inset-0 bg-black/20 md:hidden"
            onClick={toggleSidebar}
          />
        )}

        {/* Main content area */}
        <div className="flex-1 overflow-auto p-4 sm:p-6 md:p-8">
          <Outlet />
        </div>
      </div>
    </div>
  );
};

export default Employerlayout;

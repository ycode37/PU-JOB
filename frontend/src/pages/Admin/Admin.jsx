import { AppContext } from "../../context/AppContext";
import toast from "react-hot-toast";
import { useContext } from "react";
import { assets } from "../../assets/assets";
import { Link, Outlet, useLocation } from "react-router-dom";

const Admin = () => {
  const { navigate, setadmin, axios } = useContext(AppContext);
  const location = useLocation();

  const sidebarLinks = [
    { name: "Companies", path: "/admin" },
    { name: "Companies", path: "/admin/all-companies" },
    { name: "Jobs", path: "/admin/all-jobs" },
    { name: "Cateogaries", path: "/admin/all-cateogary" },
    { name: "Applicantions", path: "/admin/all-applications" },
    { name: "Jobs", path: "/admin/all-jobs" },
  ];

  const isActive = (path) => {
    if (path === "/employer") {
      return location.pathname === "/employer";
    }
    return location.pathname === path;
  };
  const logout = async () => {
    try {
      const { data } = await axios.get(`${import.meta.env.VITE_MY_URL}/auth/logout`);
      if (data.success) {
        setadmin(false);
        navigate("/");
        toast.success(data.message);
      }
    } catch (error) {
      toast.error("error");
    }
  };

  return (
    <>
      <div className="flex items-center justify-between px-4 md:px-8 border-b border-gray-300 py-3 bg-white transition-all duration-300">
        <Link to={"/employer"}>
          <img src={assets.logo} alt="" className="w-20 m-0" />
        </Link>
        <div className="flex items-center gap-5 text-gray-500">
          <p>Hi! Admin</p>
          <button
            onClick={logout}
            className="border rounded-full text-sm px-4 py-1 hover:bg-gray-50 transition-colors duration-200"
          >
            Logout
          </button>
        </div>
      </div>

      <div className="flex">
        <div className="md:w-64 w-16 border-r h-[550px] text-base border-gray-300 pt-4 flex flex-col transition-all duration-300">
          {sidebarLinks.map((item, index) => (
            <Link
              to={item.path}
              key={index}
              className={`flex items-center py-3 px-4 gap-3 transition-all duration-200
                ${
                  isActive(item.path)
                    ? "border-r-4 md:border-r-[6px] bg-indigo-500/10 border-indigo-500 text-indigo-500"
                    : "hover:bg-gray-100/90 border-white text-gray-700 hover:text-gray-900"
                }`}
            >
              <p className="md:block hidden text-center">{item.name}</p>
            </Link>
          ))}
        </div>
        <Outlet />
      </div>
    </>
  );
};

export default Admin;

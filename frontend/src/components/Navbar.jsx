import React, { useContext } from "react";
import { useState } from "react";
import { assets } from "../assets/assets";
import { Link } from "react-router-dom";

import { AppContext } from "../context/AppContext";
import toast from "react-hot-toast";

export const Navbar = () => {
  const { navigate, setquery, user, setuser, axios } = useContext(AppContext);
  const [open, setOpen] = useState(false);
  const [isOpen, setisOpen] = useState(false);
  const [input, setinput] = useState("");
  const handleSearch = (e) => {
    if (e.key === "Enter" && input.trim() !== "") {
      setquery(input);
      navigate("/all-jobs");
      setinput("");
    }
  };
  const logout = async () => {
    try {
      const { data } = await axios.get(
        `${import.meta.env.VITE_MY_URL}/auth/logout`
      );
      if (data.success) {
        setuser(false);
        navigate("/");
        toast.success("Logged Out Successfully");
      }
    } catch (error) {
      toast.error("failed");
    }
  };
  return (
    <nav className="flex items-center justify-between px-6 md:px-16 lg:px-24 xl:px-32 py-4 border-b border-gray-300 bg-white relative transition-all">
      <Link to={"/"}>
        <img src={assets.logo} className="w-20 m-0" alt="" />
      </Link>
      {/* Desktop Menu */}
      <div className="hidden sm:flex items-center gap-8">
        <Link to={"/"}>Home</Link>
        <Link to={"/About"}>About</Link>
        <Link to={"/all-jobs"}>All Jobs</Link>

        <div className="hidden lg:flex items-center text-sm gap-2 border border-gray-300 px-3 rounded-full">
          <input
            className="py-1.5 w-full bg-transparent outline-none placeholder-gray-500"
            type="text"
            value={input}
            onChange={(e) => setinput(e.target.value)}
            onKeyDown={handleSearch}
            placeholder="Search Jobs.."
          />

          <button className="absolute -top-2 -right-3 text-xs text-white bg-indigo-500 w-[18px] h-[18px] rounded-full">
            3
          </button>
        </div>

        {user ? (
          <div className="relative">
            <div
              className="relative inline-block"
              onMouseEnter={() => setisOpen(true)}
              onMouseLeave={() => setisOpen(false)}
            >
              <img
                src={assets.user_profile}
                alt=""
                className="w-12 h-12 rounded-full cursor-pointer border border-gray-300"
              />

              {/* Dropdown Menu */}
              {isOpen && (
                <div className="absolute top-full right-0 mt-1 w-48 bg-white shadow-lg rounded-lg py-2 z-50 border border-gray-200">
                  <p
                    className="px-4 py-2 hover:bg-gray-100 cursor-pointer transition-colors"
                    onClick={() => navigate("/my-applications")}
                  >
                    My Applications
                  </p>
                  <p
                    className="px-4 py-2 hover:bg-gray-100 cursor-pointer transition-colors"
                    onClick={() => navigate("/profile")}
                  >
                    Profile
                  </p>
                  <p
                    className="px-4 py-2 text-red-300 cursor-pointer transition-colors"
                    onClick={logout}
                  >
                    LogOut
                  </p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <button
            onClick={() => navigate("/login")}
            className="cursor-pointer px-8 py-2 bg-indigo-500
            hover:bg-indigo-600 transition text-white rounded-full"
          >
            Login
          </button>
        )}
      </div>

      <button
        onClick={() => (open ? setOpen(false) : setOpen(true))}
        aria-label="Menu"
        className="sm:hidden"
      >
        {/* Menu Icon SVG */}
        <svg
          width="21"
          height="15"
          viewBox="0 0 21 15"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <rect width="21" height="1.5" rx=".75" fill="#426287" />
          <rect x="8" y="6" width="13" height="1.5" rx=".75" fill="#426287" />
          <rect x="6" y="13" width="15" height="1.5" rx=".75" fill="#426287" />
        </svg>
      </button>

      {/* Mobile Menu */}
      <div
        className={`${
          open ? "flex" : "hidden"
        } absolute top-[60px] left-0 w-full bg-white shadow-md py-4 flex-col items-start gap-2 px-5 text-sm md:hidden`}
      >
        <Link to={"/"}>Home</Link>
        <Link to={"/About"}>About</Link>
        <Link to={"/all-jobs"}>All Jobs</Link>
        <input
          className="py-1.5 w-full bg-transparent outline-none placeholder-gray-500"
          type="text"
          value={input}
          onChange={(e) => setinput(e.target.value)}
          onKeyDown={handleSearch}
          placeholder="Search Jobs.."
        />
        <button
          onClick={() => navigate("/login")}
          className="cursor-pointer px-6 py-2 mt-2 bg-indigo-500 hover:bg-indigo-600 transition text-white rounded-full text-sm"
        >
          Login
        </button>
      </div>
    </nav>
  );
};

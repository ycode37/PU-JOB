import React from "react";
import { Routes, Route, useLocation } from "react-router-dom";
import Home from "./pages/Home";
import Alljob from "./pages/Alljob";
import Jobdetail from "./pages/Jobdetail";
import About from "./pages/About";
import Signup from "./pages/auth/Signup";
import Login from "./pages/auth/Login";
import { Navbar } from "./components/Navbar";
import Footer from "./components/Footer";
import { Toaster } from "react-hot-toast";
import Myapplication from "./pages/user/Myapplication";
import Profile from "./pages/user/Profile";
import Employerlayout from "./pages/employer/Employerlayout";
import Companieslist from "./pages/employer/Companieslist";
import { Addcompany } from "./pages/employer/Addcompany";
import Postjob from "./pages/employer/Postjob";
import Joblist from "./pages/employer/Joblist";
import Applicants from "./pages/employer/Applicants";
import Admin from "./pages/Admin/Admin";
import Cateogarylist from "./pages/Admin/Cateogarylist";
import Addcateogary from "./pages/Admin/Addcateogary";
import Allcompanies from "./pages/Admin/Allcompanies";
import Allapplications from "./pages/Admin/Allapplications";
import Allusers from "./pages/Admin/Allusers";
import { Jobs } from "./pages/Admin/Jobs";


const App = () => {
  const adminPath = useLocation().pathname.includes("admin");
  const employerPath = useLocation().pathname.includes("employer");
  return (
    <>
      {/* <h1 className="text-red-500">Hello</h1> */}

      <div>
        {adminPath || employerPath ? null : <Navbar />}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/all-jobs" element={<Alljob />} />
          <Route path="/job-details/:id" element={<Jobdetail />} />
          <Route path="/About" element={<About />} />
          <Route path="/Signup" element={<Signup />} />
          <Route path="/Login" element={<Login />} />
          {/* user routes */}
          <Route path="/my-applications" element={<Myapplication />} />
          <Route path="/profile" element={<Profile />} />
          {/* employer routes  */}
          <Route path="/employer" element={<Employerlayout />}>
            <Route index element={<Companieslist />} />
            <Route path="add-company" element={<Addcompany />} />
            <Route path="post-job" element={<Postjob />} />
            <Route path="jobs-list" element={<Joblist />} />
            <Route path="applicants" element={<Applicants />} />
          </Route>
          {/* Admin Route  */}
          <Route path="/admin" element={<Admin />}>
            <Route index element={<Cateogarylist />} />
            <Route path="all-cateogary" element={<Addcateogary />} />
            <Route path="all-companies" element={<Allcompanies />} />
            <Route path="all-applications" element={<Allapplications />} />
            <Route path="all-users" element={<Allusers />} />
            <Route path="all-jobs" element={<Jobs />} />
          </Route>
        </Routes>
        {adminPath || employerPath ? null : <Footer />}
        <Toaster />
      </div>
    </>
  );
};

export default App;

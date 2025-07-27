import { createContext, use, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { categories } from "../assets/assets";
import { jobs } from "../assets/assets";
import toast from "react-hot-toast";
import { companies } from "../assets/assets";
import { applicants } from "../assets/assets";
import axios from "axios";
axios.defaults.withCredentials = true;
export const AppContext = createContext();
axios.defaults.withCredentials = true;

const AppContextProvider = ({ children }) => {
  const navigate = useNavigate();
  const [user, setuser] = useState(false);

  const [admin, setadmin] = useState(false);
  const [categoriesData, setcategoriesData] = useState([]);
  const [jobsData, setjobsData] = useState([]);
  const [query, setquery] = useState("");
  const [isJobapplied, setisJobapplied] = useState(false);
  const [savedJobs, setsavedJobs] = useState([]);
  const [companyData, setcompanyData] = useState([]);
  const [applications, setapplications] = useState([]);
  const fetchCategories = () => {
    setcategoriesData(categories);
  };
  const fetchApplicants = () => {
    setapplications(applicants);
  };
  const fetchcompanyData = () => {
    setcompanyData(companies);
  };

  //get LoggedIn user
  useEffect(() => {
    const fetchLoggedInUser = async () => {
      try {
        const { data } = await axios.get(
          `${import.meta.env.VITE_MY_URL}/user/me`
        );
        if (data.success) {
          setuser(data.user);
        }
      } catch (error) {
        toast.error("error");
      }
    };
    fetchLoggedInUser();
  }, []);

  useEffect(() => {
    fetchCategories();
    fetchJobs();
    fetchcompanyData();
    fetchApplicants();
  }, []);
  const fetchJobs = () => {
    setjobsData(jobs);
  };
  const savedJob = (job) => {
    setsavedJobs((prev) => {
      const exists = prev.find((item) => item._id === job._id);
      if (exists) {
        return prev;
      } else {
        toast.success("Job Saved Successfully");

        return [...prev, job];
      }
    });
  };
  const value = {
    navigate,
    user,
    setuser,

    admin,
    setadmin,
    categoriesData,
    setcategoriesData,
    jobsData,
    setjobsData,
    query,
    setquery,
    isJobapplied,
    setisJobapplied,
    savedJobs,
    setsavedJobs,
    savedJob,
    companyData,
    setcompanyData,
    applications,
    setapplications,
    axios,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export default AppContextProvider;

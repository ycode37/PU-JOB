import React, { useContext, useState } from "react";
import { Link } from "react-router-dom";
import { AppContext } from "../../context/AppContext";
import toast from "react-hot-toast";

export default function Signup() {
  const { navigate, axios } = useContext(AppContext);
  const [file, setfile] = useState(null);
  const [preview, setpreview] = useState(null);
  const [formdata, setformdata] = useState({
    name: "",
    email: "",
    password: "",
    role: "",
    image: null,
  });

  const handleChange = (e) => {
    setformdata({ ...formdata, [e.target.name]: e.target.value });
  };

  const handleFilechange = (e) => {
    const selectedFile = e.target.files[0];
    setfile(selectedFile);
    setformdata({ ...formdata, image: selectedFile });
    if (selectedFile) {
      const imageurl = URL.createObjectURL(selectedFile);
      setpreview(imageurl);
    }
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formPayload = new FormData();
      formPayload.append("name", formdata.name);
      formPayload.append("email", formdata.email);
      formPayload.append("password", formdata.password);
      formPayload.append("role", formdata.role);
      formPayload.append("image", formdata.image);
      const { data } = await axios.post(
        `${import.meta.env.VITE_MY_URL}/auth/signup`,
        formPayload,
        { headers: { "Content-type": "multipart/form-data" } }
      );

      if (data.success) {
        toast.success(data.message);
        navigate("/login");
      } else {
        toast.error(data.message);
      }
    } catch (error) {
      toast.error(error.response.data.message);
    }
  };
  return (
    <form
      onSubmit={handleSubmit}
      className="bg-white text-gray-500 max-w-[340px] w-full mx-4 md:p-6 p-4 py-8 text-left text-sm rounded-lg shadow-[0px_0px_10px_0px] shadow-black/10"
    >
      {preview && (
        <div className="mt-4 text-center">
          <p className="mb-2 text-sm text-gray-600">Image Preview:</p>
          <img
            src={preview}
            alt="Selected"
            className="mx-auto w-32 h-32 object-cover rounded-full border border-gray-300 shadow"
          />
        </div>
      )}
      <h2 className="text-2xl font-bold mb-9 text-center text-gray-800">
        Sign Up
      </h2>
      <div className="flex items-center my-2 border bg-indigo-500/5 border-gray-500/10 rounded gap-1 pl-2">
        <svg
          width="18"
          height="18"
          viewBox="0 0 15 15"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M3.125 13.125a4.375 4.375 0 0 1 8.75 0M10 4.375a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0"
            stroke="#6B7280"
            strokeOpacity=".6"
            strokeWidth="1.3"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        <input
          className="w-full outline-none bg-transparent py-2.5"
          type="text"
          placeholder="Username"
          name="name"
          value={formdata.name}
          onChange={handleChange}
          required
        />
      </div>
      <div className="flex items-center my-2 border bg-indigo-500/5 border-gray-500/10 rounded gap-1 pl-2">
        <svg
          width="18"
          height="18"
          viewBox="0 0 15 15"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="m2.5 4.375 3.875 2.906c.667.5 1.583.5 2.25 0L12.5 4.375"
            stroke="#6B7280"
            strokeOpacity=".6"
            strokeWidth="1.3"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M11.875 3.125h-8.75c-.69 0-1.25.56-1.25 1.25v6.25c0 .69.56 1.25 1.25 1.25h8.75c.69 0 1.25-.56 1.25-1.25v-6.25c0-.69-.56-1.25-1.25-1.25Z"
            stroke="#6B7280"
            strokeOpacity=".6"
            strokeWidth="1.3"
            strokeLinecap="round"
          />
        </svg>
        <input
          className="w-full outline-none bg-transparent py-2.5"
          type="email"
          placeholder="Email"
          name="email"
          value={formdata.email}
          onChange={handleChange}
          required
        />
      </div>
      <div className="flex items-center mt-2 mb-8 border bg-indigo-500/5 border-gray-500/10 rounded gap-1 pl-2">
        <select
          className="w-full outline-none bg-transparent py-2.5"
          name="role"
          value={formdata.role}
          onChange={handleChange}
          required
        >
          <option value="" disabled>
            Select Role
          </option>
          <option value="employer">Employer</option>
          <option value="student">Student</option>
        </select>
      </div>
      <div className="flex items-center mt-2 mb-8 border bg-indigo-500/5 border-gray-500/10 rounded gap-1 pl-2">
        <svg
          width="18"
          height="18"
          viewBox="0 0 15 15"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="m2.5 4.375 3.875 2.906c.667.5 1.583.5 2.25 0L12.5 4.375"
            stroke="#6B7280"
            strokeOpacity=".6"
            strokeWidth="1.3"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M11.875 3.125h-8.75c-.69 0-1.25.56-1.25 1.25v6.25c0 .69.56 1.25 1.25 1.25h8.75c.69 0 1.25-.56 1.25-1.25v-6.25c0-.69-.56-1.25-1.25-1.25Z"
            stroke="#6B7280"
            strokeOpacity=".6"
            strokeWidth="1.3"
            strokeLinecap="round"
          />
        </svg>
        <input
          className="w-full outline-none bg-transparent py-2.5"
          type="password"
          placeholder="Password"
          name="password"
          value={formdata.password}
          onChange={handleChange}
          required
        />
      </div>
      <div>
        <input type="file" accept="image/*" onChange={handleFilechange} />
      </div>
      <button className="w-full mb-3 bg-indigo-500 hover:bg-indigo-600 transition-all active:scale-95 py-2.5 rounded text-white font-medium">
        Create Account
      </button>
      <p className="text-center mt-4">
        Already have an account?{" "}
        <Link to={"/Login"} className="text-blue-500 underline">
          Log In
        </Link>
      </p>
    </form>
  );
}

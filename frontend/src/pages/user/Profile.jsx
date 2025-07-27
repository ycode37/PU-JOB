import React, { useState } from "react";

const Profile = () => {
  const [formdata, setformdata] = useState({
    name: "",
    email: "",
    phone: "",
    location: "",
    experience: "",
    skills: "",
    about: "",
    profileImage: null,
    resume: null,
  });
  const [preview, setpreview] = useState(null);
  const handleChange = (e) => {
    const { name, value, files } = e.target;
    if (files) {
      setformdata({ ...formdata, [name]: files[0] });
    } else {
      setformdata({ ...formdata, [name]: value });
    }
  };
  const handleSubmit = (e) => {
    e.preventDefault();
  };
  return (
    <div className="max-w-3xl mx-auto mt-8 p-6 bg-white shadow rounded-lg">
      <h2 className="text-2xl font-semibold mb-4">My Profile</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          {preview && (
            <img
              src={preview}
              alt=""
              className="w-24 h-24 object-cover rounded-full mb-4 "
            />
          )}
        </div>
        <div>
          <label className="block mb-1 font-semibold">Profile Image</label>
          <input type="file" onChange={handleChange} />
        </div>
        <div>
          <label className="block mb-1 font-semibold">Name</label>
          <input
            type="text"
            name="name"
            value={formdata.name}
            onChange={handleChange}
            className="w-full border rounded p-2"
            required
          />
          <label className="block mb-1 font-semibold">Email</label>
          <input
            type="text"
            name="email"
            value={formdata.email}
            onChange={handleChange}
            className="w-full border rounded p-2"
            required
          />
          <label className="block mb-1 font-semibold">Contact No.</label>
          <input
            type="number"
            name="number"
            value={formdata.number}
            onChange={handleChange}
            className="w-full border rounded p-2"
            required
          />
          <label className="block mb-1 font-semibold">Location</label>
          <input
            type="text"
            name="location"
            value={formdata.location}
            onChange={handleChange}
            className="w-full border rounded p-2"
            required
          />
          <label className="block mb-1 font-semibold">Education</label>
          <input
            type="text"
            name="education"
            value={formdata.education}
            onChange={handleChange}
            className="w-full border rounded p-2"
            required
          />
          <label className="block mb-1 font-semibold">Skills</label>
          <input
            type="text"
            name="skill"
            value={formdata.skill}
            onChange={handleChange}
            className="w-full border rounded p-2"
            required
          />
        </div>
        <button
          type="submit"
          className="bg-blue-400 text-white px-4 py-2 rounded hover:bg-blue-700"
        >Submit</button>
      </form>
    </div>
  );
};

export default Profile;

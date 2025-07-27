import React, { useContext, useState } from "react";
import { AppContext } from "../../context/AppContext";

const Addcateogary = () => {
  const { navigate } = useContext(AppContext);
  const [cateogarydata, setcateogarydata] = useState({
    name: "",
    logo: null,
  });
  const [file, setfile] = useState(null);
  const [preview, setpreview] = useState(null);

  const handlechange = (e) => {
    setcateogarydata({ ...cateogarydata, [e.target.name]: e.target.value });
  };
  const handlefilechange = (e) => {
    const selectedFile = e.target.files[0];
    setfile(selectedFile);
    setcateogarydata({ ...cateogarydata, logo: selectedFile });
    if (selectedFile) {
      const imageURL = URL.createObjectURL(selectedFile);
      setpreview(imageURL);
    }
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
    navigate("/admin");
  };
  return (
    <div>
      <form onSubmit={handleSubmit}>
        <h2>Add new Cateogary</h2>
        <div>
          {preview && (
            <div>
              <img src={preview} alt="" />
            </div>
          )}
          <input type="file" accept="image/*" onChange={handlefilechange} />
        </div>
        <label htmlFor="">Cateogary Name</label>
        <input type="text" name="name" value={cateogarydata.name} onChange={handlechange} />
        <button type="submit">Add cateogary/</button>
      </form>
    </div>
  );
};

export default Addcateogary;

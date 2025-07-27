import React, { useContext } from "react";
import { AppContext } from "../../context/AppContext";

const Cateogarylist = () => {
  const { categoriesData } = useContext(AppContext);
  return (
    <div>
      <h2>All cateogaries</h2>
      <div>
        <table>
          <thead>
            <tr>
              <th>Logo</th>
              <th>Cateogary</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {categoriesData.map((cateogary) => (
              <tr key={cateogary._id}>
                <td>
                  <img src={cateogary.icon} alt="" />
                </td>
                <td>
                  <p>{cateogary.name}</p>
                </td>
                <td>
                  <button>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Cateogarylist;

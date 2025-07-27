import React from "react";
import { howWorks } from "../assets/assets";

export const Works = () => {
  return (
    <div className="py-16 bg-[#F1F2F4]">
      <h2 className="text-2xl md:text-5xl font-semibold text-gray-800 text-center">
        How Pu Job works
      </h2>
      <div className="grid grid-cols-1 sm-grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 mt-10 items-center justify-center">
        {howWorks.map((item, index) => (
          <div
            key={index}
            className="flex flex-col items-center justify-center gap-4"
          >
            <img src={item.icon} alt="" />
            <div className="flex flex-col items-center justify-center text-gray-800">
              <h4>{item.title}</h4>
              <p>{item.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

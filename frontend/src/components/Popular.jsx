import React, { useContext } from "react";
import { AppContext } from "../context/AppContext";

export const Popular = () => {
  const colors = [
    "bg-indigo-300",
    "bg-sky-400",
    "bg-blue-450",
    "bg-gray-400",
    "bg-slate-200",
    "bg-slate-50",
    "bg-cyan-400",
  ];
  const { categoriesData } = useContext(AppContext);
  return (
    <div className="py-16">
      <h2 className="text-2xl md:text-5xl font-semibold text-gray-800 text-center">
        Most Popular Categories
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 mt-10 justify-items-center">
        {categoriesData.map((item, index) => {
          const colorclass = colors[index % colors.length];
          return (
            <div
              key={index}
              className={`flex w-[250px] h-[150px] items-center justify-center gap-2 border border-gray-300 rounded-xl py-6 px-4 shadow ${colorclass}`}
            >
              <img src={item.icon} alt="" />
              <div>
                <h3 className="text-lg font-semibold text-center leading-tight">
                  {item.name}
                </h3>
                <p className="text-sm text-center">
                  {item.positions} open Positions
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

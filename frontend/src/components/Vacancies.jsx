import React from "react";
import { vacancies } from "../assets/assets";

export const Vacancies = () => {
  const colors = [
    "bg-indigo-300",
    "bg-sky-400",
    "bg-blue-450",
    "bg-gray-400",
    "bg-slate-200",
    "bg-slate-50",
    "bg-cyan-400",
  ];
  return (
    <div className="py-16 flex flex-col items-center justify-center text-center">
      <h1 className="text-2xl md:text-5xl font-semibold text-gray-800">
        Most Popular Vacancies
      </h1>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 mt-10 justify-items-center">
        {vacancies.map((item, index) => {
          const colorclass = colors[index % colors.length];
          return (
            <div
              key={index}
              className={`flex flex-col w-[250px] h-[150px] items-center justify-center gap-2 border border-gray-300 rounded-xl py-6 px-4 shadow ${colorclass}`}
            >
              <h3 className="text-lg font-semibold text-center leading-tight">
                {item.title}
              </h3>
              <p className="text-sm text-center">{item.count} open positions</p>
            </div>
          );
        })}
      </div>
    </div>
  );
};

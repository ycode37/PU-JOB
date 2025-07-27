import React, { useContext } from "react";
import { AppContext } from "../context/AppContext";
import { Jobcard } from "./Jobcard";

export const Jobs = () => {
  const { jobsData } = useContext(AppContext);
  return (
    <div className="py-16">
      <h1 className="text-2xl md:text-5xl font-semibold text-gray-800">JOBS</h1>
      <div className="my-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 items-center justify-center gap-12">
        {jobsData.map((job) => (
          <Jobcard key={job.id} job={job} />
        ))}
      </div>
    </div>
  );
};

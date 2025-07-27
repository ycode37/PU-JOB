import React, { useContext, useEffect } from "react";
import { AppContext } from "../context/AppContext";
import { Jobcard } from "../components/Jobcard";

const Alljob = () => {
  const { setquery } = useContext(AppContext);
  useEffect(() => {
    setquery("");
  }, []);
  const { jobsData, query } = useContext(AppContext);
  const filteredJobs = jobsData.filter((job) => {
    return job.title.toLowerCase().includes(query.toLowerCase());
  });
  return (
    <div>
      <h2 className="text-2xl md:text-5xl font-semibold text-gray-800 text-center">
        Availaible Jobs
      </h2>
      <div className="my-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 items-center justify-center gap-12">
        {filteredJobs.map((job) => (
          <Jobcard key={job.id} job={job} />
        ))}
      </div>
    </div>
  );
};

export default Alljob;

import React, { useEffect, useState } from 'react';
import { LineChart, XAxis, YAxis, CartesianGrid, Line, ResponsiveContainer, Legend } from 'recharts';

const App = () => {

  const [msg, setMsg] = useState('');
  const [perfdata, setPerfdata] = useState([]);
  const [maxperflen, setMaxperflen] = useState(10);

  useEffect(() => {
    var ws = null;
    ws = new WebSocket("ws://localhost:8000/ws");
    // ws.onopen = () => ws.send("Connected to React!");
    ws.onmessage=(e) => {
      // console.log("Accepted Message: ", e.data);
      setMsg(e.data);
      // console.log("e.data: ", e.data);
      
      setPerfdata(currentData => [...currentData, JSON.parse(e.data)]);
    };

    // console.log("perfdata: ", perfdata);
  }, []);

  useEffect(()=>
  {
    console.log("datanew",perfdata);
    if(perfdata.length == maxperflen){
      var tmp_data = perfdata;
      tmp_data.shift();
      setPerfdata(tmp_data);
    }
  },[perfdata,])

  var data_new = [
    {
      "cnt": 1,
      "a": 2,
      "b": 3
    },
    {
      "cnt": 2,
      "a": 4,
      "b": 2
    },
    {
      "cnt": 3,
      "a": 1,
      "b": 3
    },
    {
      "cnt": 4,
      "a": 1,
      "b": 6
    },
    {
      "cnt": 5,
      "a": 5,
      "b": 2
    },
  ];

  var tmp = [];

  return (
    <div>
      Hello World!
      <br />
      {/* data: {perfdata[1]}
      lasan: {perfdata.map(o => {return o.cnt})[0]} */}

      {/* <ResponsiveContainer width={1000} aspect={3} key={Math.random()}> */}
        <LineChart width={500} height={300} data={perfdata}>
        <XAxis dataKey="cnt"/>
        <YAxis/>
        {/* <Legend/> */}
        <CartesianGrid stroke="#eee" strokeDasharray="5 5"/>
        <Line type="monotone" dataKey="a" stroke="#8884d8" isAnimationActive={false}/>
        <Line type="monotone" dataKey="b" stroke="#82ca9d" isAnimationActive={false}/>
      </LineChart>
      {/* </ResponsiveContainer> */}

    </div>
  )
}

export default App